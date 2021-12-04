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

import NIO

struct SSHPacketParser {
    enum State {
        case initialized
        case cleartextWaitingForLength
        case cleartextWaitingForBytes(UInt32)
        case encryptedWaitingForLength(NIOSSHTransportProtection)
        case encryptedWaitingForBytes(UInt32, NIOSSHTransportProtection)
    }

    private var buffer: ByteBuffer
    private var state: State
    private let maximumPacketSize: Int
    internal static let defaultMaximumPacketSize = 1 << 17

    /// Testing only: the number of bytes we can discard from this buffer.
    internal var _discardableBytes: Int {
        self.buffer.readerIndex
    }

    init(allocator: ByteBufferAllocator, maximumPacketSize: Int = defaultMaximumPacketSize) {
        // Assert that users don't provide a packet size lower than allowed by spec
        precondition(maximumPacketSize >= 32768, "Maximum Packet Size is below minimum requirement as specified by RFC 4254")
        precondition(maximumPacketSize <= (1 << 24), "Maximum Packet Size is set abnormally high")

        self.buffer = allocator.buffer(capacity: 0)
        self.state = .initialized
        self.maximumPacketSize = maximumPacketSize
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
                if length >= self.maximumPacketSize {
                    throw NIOSSHError.invalidEncryptedPacketLength
                }

                if let message = try self.parsePlaintext(length: length) {
                    self.state = .cleartextWaitingForLength
                    return message
                }
                self.state = .cleartextWaitingForBytes(length)
                return nil
            }
            return nil
        case .cleartextWaitingForBytes(let length):
            if let message = try self.parsePlaintext(length: length) {
                self.state = .cleartextWaitingForLength
                return message
            }
            return nil
        case .encryptedWaitingForLength(let protection):
            guard let length = try self.decryptLength(protection: protection) else {
                return nil
            }

            if let message = try self.parseCiphertext(length: length, protection: protection) {
                self.state = .encryptedWaitingForLength(protection)
                return message
            }
            self.state = .encryptedWaitingForBytes(length, protection)
            return nil
        case .encryptedWaitingForBytes(let length, let protection):
            if let message = try self.parseCiphertext(length: length, protection: protection) {
                self.state = .encryptedWaitingForLength(protection)
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

    internal static let maximumAllowedVersionSize = 4096
    private mutating func readVersion() throws -> String? {
        // Looking for a string ending with \r\n
        let slice = self.buffer.readableBytesView

        // Prevent the consumed bytes for a version from exceeding the defined maximum allowed size
        // In practice, if SSH version packets come anywhere near this it's already likely an attack
        // More data cannot be blindly regarded as malicious though, since this might contain multiple packets
        let maxIndex = slice.index(slice.startIndex, offsetBy: min(slice.count, Self.maximumAllowedVersionSize))

        for index in slice.startIndex ..< slice.endIndex {
            if index > maxIndex {
                // Does not account for `CRLF`
                throw NIOSSHError.excessiveVersionLength
            }

            if slice[index] == 13, index.advanced(by: 1) < slice.endIndex, slice[index.advanced(by: 1)] == 10 {
                let version = String(decoding: slice[slice.startIndex ..< index], as: UTF8.self)
                // read \r\n
                self.buffer.moveReaderIndex(forwardBy: slice.startIndex.distance(to: index).advanced(by: 2))
                return version
            }
        }

        return nil
    }

    private mutating func decryptLength(protection: NIOSSHTransportProtection) throws -> UInt32? {
        let blockSize = protection.cipherBlockSize
        guard self.buffer.readableBytes >= blockSize else {
            return nil
        }

        try protection.decryptFirstBlock(&self.buffer)

        // This force unwrap is safe because we must have a block size, and a block size is always going to be more than 4 bytes.
        let packetLength = self.buffer.getInteger(at: self.buffer.readerIndex, as: UInt32.self)!
        let decryptedLength = packetLength + UInt32(protection.macBytes)

        if decryptedLength >= self.maximumPacketSize {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        return decryptedLength
    }

    private mutating func parsePlaintext(length: UInt32) throws -> SSHMessage? {
        try self.buffer.rewindReaderOnError { buffer in
            guard var buffer = buffer.readSlice(length: Int(length) + MemoryLayout<UInt32>.size) else {
                return nil
            }

            // We have enough length. Skip over the frame length now.
            buffer.moveReaderIndex(forwardBy: MemoryLayout<UInt32>.size)

            var content = try buffer.sliceContentFromPadding()
            guard let message = try content.readSSHMessage(), content.readableBytes == 0, buffer.readableBytes == 0 else {
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

            var content = try protection.decryptAndVerifyRemainingPacket(&buffer)
            guard let message = try content.readSSHMessage(), content.readableBytes == 0, buffer.readableBytes == 0 else {
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
