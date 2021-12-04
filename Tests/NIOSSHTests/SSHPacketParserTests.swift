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
@testable import NIOSSH
import XCTest

final class SSHPacketParserTests: XCTestCase {
    /// Feed the SSH version to a packet parser and verify the output.
    ///
    /// Usually used to set up an appropriate state.
    private func feedVersion(to parser: inout SSHPacketParser, file: StaticString = #file, line: UInt = #line) {
        var version = ByteBuffer.of(string: "SSH-2.0-OpenSSH_7.9\r\n")
        parser.append(bytes: &version)

        var packet: SSHMessage?
        XCTAssertNoThrow(packet = try parser.nextPacket(), file: file, line: line)

        switch packet {
        case .some(.version(let string)):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9", file: file, line: line)
        default:
            XCTFail("Expecting .version", file: file, line: line)
        }
    }

    func testReadVersion() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "SSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.9\r\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testBinaryInParts() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part1 = ByteBuffer.of(bytes: [0, 0, 0])
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(bytes: [28])
        parser.append(bytes: &part2)

        XCTAssertNil(try parser.nextPacket())
        var part3 = ByteBuffer.of(bytes: [10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97])
        parser.append(bytes: &part3)
        XCTAssertNil(try parser.nextPacket())

        var part4 = ByteBuffer.of(bytes: [117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])
        parser.append(bytes: &part4)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testBinaryFull() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part1 = ByteBuffer.of(bytes: [0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])
        parser.append(bytes: &part1)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testBinaryTwoMessages() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part = ByteBuffer.of(bytes: [0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207, 0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testWeReclaimStorage() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)
        XCTAssertNoThrow(try parser.nextPacket())

        let part = ByteBuffer.of(bytes: [0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])

        let neededParts = 2048 / part.readableBytes

        for _ in 0 ..< neededParts {
            var partCopy = part
            parser.append(bytes: &partCopy)
        }

        // The version field is in the buffer, and we can't really prevent it being there.
        let startingOffset = parser._discardableBytes
        for i in 0 ..< (neededParts / 2) {
            XCTAssertEqual(parser._discardableBytes, (i * part.readableBytes) + startingOffset)
            XCTAssertNoThrow(try parser.nextPacket())
        }

        // Now we should have cleared up.
        XCTAssertEqual(parser._discardableBytes, 0)
    }

    func testMaximumPacketSizeInVersion() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator(), maximumPacketSize: 1 << 15)
        let longVersionString = String(repeating: "z", count: SSHPacketParser.maximumAllowedVersionSize + 256)
        var version = ByteBuffer.of(string: longVersionString + "\r\n")
        parser.append(bytes: &version)

        XCTAssertThrowsError(try parser.nextPacket())
    }
}

extension ByteBuffer {
    public static func of(string: String) -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: string.count)
        buffer.writeString(string)
        return buffer
    }

    public static func of(bytes: [UInt8]) -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return buffer
    }
}
