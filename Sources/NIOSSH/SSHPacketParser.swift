//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

struct SSHPacketParser {
    enum State {
        case initialized
        case cleartextWaitingForLength
        case cleartextWaitingForBytes(UInt32)
        case encryptedWaitingForLength(NIOSSHTransportProtection)
        case encryptedWaitingForBytes(UInt32, NIOSSHTransportProtection)
    }

    /// RFC 4253 §4.2 limits the SSH version string ("SSH-...") to 255 bytes, includes CR and LF.
    static var maximumVersionStringLength: Int { 255 }

    /// This bounds each preamble line a client may receive before the version string, matching OpenSSH.
    static var maximumBannerLineLength: Int { 8192 }

    /// The maximum number of preamble lines a client accepts before the version string, matching OpenSSH.
    static var maximumPreambleLineCount: Int { 1024 }

    /// The maximum length of a cleartext (pre-encryption) packet, i.e. during version and key
    /// exchange. The encrypted path negotiates its own (larger) packet bound.
    static var maximumPlaintextPacketLength: UInt32 { 256 * 1024 }

    private let isServer: Bool
    private var buffer: ByteBuffer
    private var state: State
    private(set) var sequenceNumber: UInt32

    /// The maximum length of an encrypted packet, i.e. its `packet_length` field once key exchange
    /// has completed. This is the connection's configured maximum channel packet size plus headroom
    /// for the SSH framing and padding (RFC 4253 §6) that wraps a maximum-size channel data payload.
    private let maximumEncryptedPacketLength: UInt32

    /// The number of preamble lines a client has discarded while waiting for the identification
    /// string, bounded by `maximumPreambleLineCount`.
    private var preambleLineCount: Int

    /// Testing only: the number of bytes we can discard from this buffer.
    internal var _discardableBytes: Int {
        self.buffer.readerIndex
    }

    init(
        isServer: Bool,
        allocator: ByteBufferAllocator,
        maximumPacketSize: UInt32 = UInt32(Constants.defaultMaximumChannelPacketSize)
    ) {
        precondition(
            maximumPacketSize >= Constants.minimumChannelPacketSize,
            "maximumPacketSize must be at least \(Constants.minimumChannelPacketSize) bytes (RFC 4253 §6.1)"
        )
        precondition(
            maximumPacketSize <= Constants.maximumChannelPacketSize,
            "maximumPacketSize must leave room for SSH framing and padding (RFC 4253 §6)."
        )
        self.isServer = isServer
        self.buffer = allocator.buffer(capacity: 0)
        self.state = .initialized
        self.sequenceNumber = 0
        // Add headroom for the SSH framing and padding (RFC 4253 §6).
        self.maximumEncryptedPacketLength = maximumPacketSize + 1024
        self.preambleLineCount = 0
    }

    mutating func append(bytes: inout ByteBuffer) {
        self.buffer.writeBuffer(&bytes)
    }

    /// Encryption schemes can be added to a packet parser whenever encryption is negotiated.
    /// They must be added monotonically, and may only be added once, while the parser is in an
    /// idle state.
    mutating func addEncryption(_ protection: NIOSSHTransportProtection) {
        switch self.state {
        case .cleartextWaitingForLength:
            self.state = .encryptedWaitingForLength(protection)
        case .encryptedWaitingForLength:
            self.state = .encryptedWaitingForLength(protection)
        case .cleartextWaitingForBytes, .initialized, .encryptedWaitingForBytes:
            preconditionFailure("Adding encryption in invalid state: \(self.state)")
        }
    }

    mutating func nextPacket() throws -> SSHMessage? {
        // This parser has a slightly strange strategy: we leave the packet length field in the buffer until we're done.
        // This is necessary because some transport protection schemes need the length field for MACing purposes, and can
        // benefit from us maintaining the state instead of having to do it themselves.
        defer {
            self.reclaimBytes()
        }

        switch self.state {
        case .initialized:
            if let version = try self.readVersion() {
                self.state = .cleartextWaitingForLength
                return .version(version)
            }
            return nil
        case .cleartextWaitingForLength:
            if let length = self.buffer.getInteger(at: self.buffer.readerIndex, as: UInt32.self) {
                if let message = try self.parsePlaintext(length: length) {
                    self.state = .cleartextWaitingForLength
                    self.sequenceNumber &+= 1
                    return message
                }
                self.state = .cleartextWaitingForBytes(length)
                return nil
            }
            return nil
        case .cleartextWaitingForBytes(let length):
            if let message = try self.parsePlaintext(length: length) {
                self.state = .cleartextWaitingForLength
                self.sequenceNumber &+= 1
                return message
            }
            return nil
        case .encryptedWaitingForLength(let protection):
            guard let length = try self.decryptLength(protection: protection) else {
                return nil
            }

            if let message = try self.parseCiphertext(length: length, protection: protection) {
                self.state = .encryptedWaitingForLength(protection)
                self.sequenceNumber &+= 1
                return message
            }
            self.state = .encryptedWaitingForBytes(length, protection)
            return nil
        case .encryptedWaitingForBytes(let length, let protection):
            if let message = try self.parseCiphertext(length: length, protection: protection) {
                self.state = .encryptedWaitingForLength(protection)
                self.sequenceNumber &+= 1
                return message
            }
            return nil
        }
    }

    private mutating func reclaimBytes() {
        if self.buffer.readerIndex > 1024, self.buffer.readerIndex > (self.buffer.readableBytes / 2) {
            self.buffer.discardReadBytes()
        }
    }

    // From RFC 4253:
    //
    // > Protocol Version Exchange
    // >
    // > When the connection has been established, both sides MUST send an
    // > identification string.  This identification string MUST be
    // >   SSH-protoversion-softwareversion SP comments CR LF
    // > Since the protocol being defined in this set of documents is version
    // > 2.0, the 'protoversion' MUST be "2.0".  The 'comments' string is
    // > OPTIONAL.  If the 'comments' string is included, a 'space' character
    // > (denoted above as SP, ASCII 32) MUST separate the 'softwareversion'
    // > and 'comments' strings.  The identification MUST be terminated by a
    // > single Carriage Return (CR) and a single Line Feed (LF) character
    // > (ASCII 13 and 10, respectively).  Implementers who wish to maintain
    // > compatibility with older, undocumented versions of this protocol may
    // > want to process the identification string without expecting the
    // > presence of the carriage return character for reasons described in
    // > Section 5 of this document.  The null character MUST NOT be sent.
    // > The maximum length of the string is 255 characters, including the
    // > Carriage Return and Line Feed.
    // >
    // > The part of the identification string preceding the Carriage Return
    // > and Line Feed is used in the Diffie-Hellman key exchange (see Section
    // > 8).
    // >
    // > The server MAY send other lines of data before sending the version
    // > string.  Each line SHOULD be terminated by a Carriage Return and Line
    // > Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
    // > in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
    // > MUST be able to process such lines.  Such lines MAY be silently
    // > ignored, or MAY be displayed to the client user.  If they are
    // > displayed, control character filtering, as discussed in [SSH-ARCH],
    // > SHOULD be used.  The primary use of this feature is to allow TCP-
    // > wrappers to display an error message before disconnecting
    private mutating func readVersion() throws -> String? {
        let carriageReturn = UInt8(ascii: "\r")
        let lineFeed = UInt8(ascii: "\n")
        let sshPrefix = "SSH-".utf8

        // Per RFC 4253 §4.2:
        // The server MAY send other lines of data before sending the version string.
        // This means that server does not expect any lines before version so we will return all data before first line feed
        if self.isServer {
            // Looking for a string ending with \r\n
            let slice = self.buffer.readableBytesView
            if let lfIndex = slice.firstIndex(of: lineFeed), lfIndex < slice.endIndex {
                // This must be the version: check the length. The version itself will be validated later.
                try self.enforceIdentificationAndBannerLineLimit(
                    length: slice.startIndex.distance(to: lfIndex) + 1,  // add one for line feed
                    isVersion: true
                )
                // Guard the `-1` lookup: when the LF is the very first byte of
                // the slice (e.g., a client sends a bare LF as its first byte
                // after the TCP handshake), `lfIndex.advanced(by: -1)` would
                // index before the buffer start and trap.
                let endsWithCR =
                    lfIndex > slice.startIndex
                    && slice[lfIndex.advanced(by: -1)] == carriageReturn
                let versionEndIndex = endsWithCR ? lfIndex.advanced(by: -1) : lfIndex
                let version = String(decoding: slice[slice.startIndex..<versionEndIndex], as: UTF8.self)
                self.buffer.moveReaderIndex(forwardBy: slice.startIndex.distance(to: lfIndex).advanced(by: 1))
                return version
            }
        } else {
            // Search for version line, which starts with "SSH-". Lines without this
            // prefix may come before the version line. Discard them to avoid accumulating state.
            while true {
                // Find the next line and check its length.
                let slice = self.buffer.readableBytesView
                guard let lfIndex = slice.firstIndex(of: lineFeed) else {
                    break
                }
                let lineLength = slice.startIndex.distance(to: lfIndex)
                let isVersion = slice.starts(with: sshPrefix)
                try self.enforceIdentificationAndBannerLineLimit(
                    length: lineLength + 1,  // add one for line feed
                    isVersion: isVersion
                )

                // Per RFC other lines in the preamble are not allowed to start with "SSH-".
                // This must be the version.
                if isVersion {
                    let versionEndIndex =
                        slice[lfIndex.advanced(by: -1)] == carriageReturn ? lfIndex.advanced(by: -1) : lfIndex
                    let version = String(decoding: slice[slice.startIndex..<versionEndIndex], as: UTF8.self)
                    self.buffer.moveReaderIndex(forwardBy: lineLength + 1)
                    return version
                }

                // A preamble line will be silently ignored: count it and discard it so it cannot accumulate.
                self.preambleLineCount += 1
                if self.preambleLineCount > Self.maximumPreambleLineCount {
                    throw NIOSSHError.protocolViolation(
                        protocolName: "version exchange",
                        violation: "received more than \(Self.maximumPreambleLineCount) lines before the version string"
                    )
                }
                // This just advances the reader index. The calling function (`nextPacket`) will
                // free up bytes with `reclaimBytes` when a threshold of read bytes is reached.
                self.buffer.moveReaderIndex(forwardBy: lineLength + 1)
            }
        }

        // Ensure the buffered data has not grown past the limit, e.g., if the peer sends data without an LF.
        let pending = self.buffer.readableBytesView
        try self.enforceIdentificationAndBannerLineLimit(
            length: pending.count,
            isVersion: pending.starts(with: sshPrefix)
        )
        return nil
    }

    /// Enforces the version-exchange line-length limits used by ``readVersion()``. Identification lines are
    /// limited to ``maximumIdentificationStringLength``, others to ``maximumBannerLineLength``.
    ///
    /// - Throws: NIOSSHError.protocolViolation if the line crosses its length limit.
    private func enforceIdentificationAndBannerLineLimit(length: Int, isVersion: Bool) throws {
        if isVersion {
            if length > Self.maximumVersionStringLength {
                throw NIOSSHError.protocolViolation(
                    protocolName: "version exchange",
                    violation: "version line exceeded \(Self.maximumVersionStringLength) bytes"
                )
            }
        } else {
            if length > Self.maximumBannerLineLength {
                throw NIOSSHError.protocolViolation(
                    protocolName: "version exchange",
                    violation: "banner line exceeded \(Self.maximumBannerLineLength) bytes"
                )
            }
        }
    }

    private mutating func decryptLength(protection: NIOSSHTransportProtection) throws -> UInt32? {
        let blockSize = protection.cipherBlockSize
        guard self.buffer.readableBytes >= blockSize else {
            return nil
        }

        try protection.decryptFirstBlock(&self.buffer)

        // This force unwrap is safe because we must have a block size, and a block size is always going to be more than 4 bytes.
        let length = self.buffer.getInteger(at: self.buffer.readerIndex, as: UInt32.self)!

        // Reject an oversized encrypted packet before we commit to buffering toward it.
        guard length <= self.maximumEncryptedPacketLength else {
            throw NIOSSHError.protocolViolation(
                protocolName: "transport",
                violation: "encrypted packet length \(length) exceeds \(self.maximumEncryptedPacketLength) bytes"
            )
        }

        return length + UInt32(protection.macBytes)
    }

    private mutating func parsePlaintext(length: UInt32) throws -> SSHMessage? {
        // Reject an oversized plaintext packet before committing to buffering it.
        guard length <= Self.maximumPlaintextPacketLength else {
            throw NIOSSHError.protocolViolation(
                protocolName: "transport",
                violation: "plaintext packet length \(length) exceeds \(Self.maximumPlaintextPacketLength) bytes"
            )
        }

        return try self.buffer.rewindReaderOnError { buffer in
            guard var buffer = buffer.readSlice(length: Int(length) + MemoryLayout<UInt32>.size) else {
                return nil
            }

            // We have enough length. Skip over the frame length now.
            buffer.moveReaderIndex(forwardBy: MemoryLayout<UInt32>.size)

            var content = try buffer.sliceContentFromPadding()
            guard let message = try content.readSSHMessage(), content.readableBytes == 0, buffer.readableBytes == 0
            else {
                // Throw this error if the content wasn't exactly the right length for the message.
                throw NIOSSHError.invalidPacketFormat
            }

            return message
        }
    }

    private mutating func parseCiphertext(length: UInt32, protection: NIOSSHTransportProtection) throws -> SSHMessage? {
        try self.buffer.rewindReaderOnError { buffer in
            guard var buffer = buffer.readSlice(length: Int(length) + MemoryLayout<UInt32>.size) else {
                return nil
            }

            var content = try protection.decryptAndVerifyRemainingPacket(&buffer, sequenceNumber: self.sequenceNumber)
            guard let message = try content.readSSHMessage(), content.readableBytes == 0, buffer.readableBytes == 0
            else {
                // Throw this error if the content wasn't exactly the right length for the message.
                throw NIOSSHError.invalidPacketFormat
            }

            return message
        }
    }
}

extension ByteBuffer {
    /// Given a ByteBuffer that is exactly the size of a packet with padding (i.e. the padding byte is first),
    /// slices out the part of the packet that is content and returns it, while moving the reader index over the entire
    /// packet.
    fileprivate mutating func sliceContentFromPadding() throws -> ByteBuffer {
        guard let paddingLength = self.readInteger(as: UInt8.self) else {
            throw NIOSSHError.insufficientPadding
        }

        guard let contentSlice = self.readSlice(length: self.readableBytes - Int(paddingLength)) else {
            throw NIOSSHError.excessPadding
        }

        guard self.readerIndex + Int(paddingLength) == self.writerIndex else {
            throw NIOSSHError.invalidPacketFormat
        }

        self.moveReaderIndex(forwardBy: Int(paddingLength))

        return contentSlice
    }
}
