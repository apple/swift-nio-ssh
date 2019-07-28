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
        case binaryWaitingForLength
        case binaryWaitingForBytes(UInt32)
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

    mutating func nextPacket() throws -> Message? {
        switch self.state {
        case .initialized:
            if let version = try self.readVersion() {
                self.state = .binaryWaitingForLength
                return .version(version)
            }
            return nil
        case .binaryWaitingForLength:
            if let length = self.buffer.readInteger(as: UInt32.self) {
                if self.buffer.readableBytes >= length {
                    self.state = .binaryWaitingForLength
                    return try parse(length: length)
                } else {
                    self.state = .binaryWaitingForBytes(length)
                    return nil
                }
            }
            return nil
        case .binaryWaitingForBytes(let length):
            if self.buffer.readableBytes >= length {
                self.state = .binaryWaitingForLength
                return try parse(length: length)
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
                return try parse(length: length)
            } else {
                self.state = .encryptedWaitingForBytes(length)
                return nil
            }
        case .encryptedWaitingForBytes(let length):
            if self.buffer.readableBytes >= length {
                self.state = .binaryWaitingForLength
                return try parse(length: length)
            }
            return nil
        }
    }

    private mutating func readVersion() throws -> String? {
        // Looking for a string ending with \r\n
        if let cr = self.buffer.readableBytesView.firstIndex(of: 13), self.buffer.getInteger(at: cr.advanced(by: 1), as: UInt8.self) == 10 {
            // read version
            guard let version = self.buffer.readString(length: cr) else {
                throw ProtocolError.cannotReadVersion
            }
            // read \r\n
            _ = buffer.readBytes(length: 2)
            return version
        }
        return nil
    }

    private func decryptLength() throws -> UInt32 {
        preconditionFailure("Not implemented")
    }

    private mutating func parse(length: UInt32) throws -> Message {
        guard let padding = self.buffer.readInteger(as: UInt8.self) else {
            throw ProtocolError.paddingLength
        }

        let messageLength = length - UInt32(padding) - 1
        let message = try Message.parse(length: messageLength, bytes: &self.buffer)

        guard let randomPadding = buffer.readBytes(length: Int(padding)) else {
            throw ProtocolError.padding
        }

        guard let mac = self.buffer.readBytes(length: buffer.readableBytes) else {
            throw ProtocolError.mac
        }

        return message
    }
}
