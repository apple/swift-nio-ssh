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

    enum ProtocolError: Error {
        case cannotReadVersion
        case paddingLength
        case padding
        case mac
    }

    var buffer: ByteBuffer
    var state: State

    init(allocator: ByteBufferAllocator) {
        self.buffer = allocator.buffer(capacity: 0)
        self.state = .initialized
    }

    mutating func append(bytes: inout ByteBuffer) {
        self.buffer.writeBuffer(&bytes)
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
                if let message = try self.parse(length: length, macLength: 0) {
                    self.state = .cleartextWaitingForLength
                    return message
                }
                self.state = .cleartextWaitingForBytes(length)
                return nil
            }
            return nil
        case .cleartextWaitingForBytes(let length):
            if let message = try self.parse(length: length, macLength: 0) {
                self.state = .cleartextWaitingForLength
                return message
            }
            return nil
        case .encryptedWaitingForLength(let protection):
            guard let length = try self.decryptLength(protection: protection) else {
                return nil
            }

            if let message = try self.parse(length: length, macLength: 0) {
                self.state = .encryptedWaitingForLength(protection)
                return message
            }
            self.state = .encryptedWaitingForBytes(length, protection)
            return nil
        case .encryptedWaitingForBytes(let length, let protection):
            if let message = try self.parse(length: length, macLength: 0) {
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
        return self.buffer.getInteger(at: self.buffer.readerIndex)
    }

    private mutating func parse(length: UInt32, macLength: Int) throws -> SSHMessage? {
        guard self.buffer.readableBytes >= Int(length) + MemoryLayout<UInt32>.size else {
            return nil
        }

        return try self.buffer.rewindReaderOnError { buffer in
            // We have enough length. Skip over the frame length now.
            buffer.moveReaderIndex(forwardBy: MemoryLayout<UInt32>.size)

            guard let padding = buffer.readInteger(as: UInt8.self) else {
                throw ProtocolError.paddingLength
            }

            let messageLength = length - UInt32(padding) - 1
            let message = try buffer.readSSHMessage(length: messageLength)

            guard let randomPadding = buffer.readBytes(length: Int(padding)) else {
                throw ProtocolError.padding
            }
            // mute warning for now
            precondition(randomPadding.count == padding)

            guard let mac = buffer.readBytes(length: macLength) else {
                throw ProtocolError.mac
            }
            // mute warning for now
            precondition(mac.count == macLength)

            return message
        }
    }
}
