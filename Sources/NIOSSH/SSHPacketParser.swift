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

    init(allocator: ByteBufferAllocator) {
        self.buffer = allocator.buffer(capacity: 0)
        self.state = .initialized
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
        case .cleartextWaitingForBytes, .initialized, .encryptedWaitingForLength, .encryptedWaitingForBytes:
            preconditionFailure("Adding encryption in invalid state: \(self.state)")
        }
    }

    mutating func nextPacket() throws -> SSHMessage? {
        // This parser has a slightly strange strategy: we leave the packet length field in the buffer until we're done.
        // This is necessary because some transport protection schemes need the length field for MACing purposes, and can
        // benefit from us maintaining the state instead of having to do it themselves.
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
                self.state = .cleartextWaitingForLength
                return message
            }
            return nil
        }
    }

    private mutating func readVersion() throws -> String? {
        // Looking for a string ending with \r\n
        let slice = self.buffer.readableBytesView
        if let cr = slice.firstIndex(of: 13), slice[cr.advanced(by: 1)] == 10 {
            let version = String(decoding: slice[slice.startIndex ..< cr], as: UTF8.self)
            // read \r\n
            buffer.moveReaderIndex(forwardBy: slice.startIndex.distance(to: cr).advanced(by: 2))
            return version
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
        return self.buffer.getInteger(at: self.buffer.readerIndex)! + UInt32(protection.macBytes)
    }

    private mutating func parsePlaintext(length: UInt32) throws -> SSHMessage? {
        return try buffer.rewindReaderOnError { buffer in
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
        return try buffer.rewindReaderOnError { buffer in
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
