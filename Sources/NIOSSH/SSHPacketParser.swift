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
        case encryptedWaitingForLength
        case encryptedWaitingForBytes(UInt32)
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
        switch self.state {
        case .initialized:
            if let version = try self.readVersion() {
                self.state = .cleartextWaitingForLength
                return .version(version)
            }
            return nil
        case .cleartextWaitingForLength:
            if let length = self.buffer.readInteger(as: UInt32.self) {
                if self.buffer.readableBytes >= length {
                    self.state = .cleartextWaitingForLength
                    return try self.parse(length: length)
                } else {
                    self.state = .cleartextWaitingForBytes(length)
                    return nil
                }
            }
            return nil
        case .cleartextWaitingForBytes(let length):
            if self.buffer.readableBytes >= length {
                self.state = .cleartextWaitingForLength
                return try self.parse(length: length)
            }
            return nil
        case .encryptedWaitingForLength:
            // TODO: Replace with real block size
            let blockSize = 16
            if self.buffer.readableBytes < blockSize {
                return nil
            }

            let length = try decryptLength()

            if self.buffer.readableBytes >= length {
                self.state = .encryptedWaitingForLength
                return try self.parse(length: length)
            } else {
                self.state = .encryptedWaitingForBytes(length)
                return nil
            }
        case .encryptedWaitingForBytes(let length):
            if self.buffer.readableBytes >= length {
                self.state = .cleartextWaitingForLength
                return try self.parse(length: length)
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

    private func decryptLength() throws -> UInt32 {
        preconditionFailure("Not implemented")
    }

    private mutating func parse(length: UInt32) throws -> SSHMessage {
        guard let padding = self.buffer.readInteger(as: UInt8.self) else {
            throw ProtocolError.paddingLength
        }

        let messageLength = length - UInt32(padding) - 1
        let message = try self.buffer.readSSHMessage(length: messageLength)

        guard let randomPadding = buffer.readBytes(length: Int(padding)) else {
            throw ProtocolError.padding
        }

        guard let mac = self.buffer.readBytes(length: buffer.readableBytes) else {
            throw ProtocolError.mac
        }

        return message
    }
}
