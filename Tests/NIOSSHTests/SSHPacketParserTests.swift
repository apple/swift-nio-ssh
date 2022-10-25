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

import Crypto
import NIOCore
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
            XCTAssertEqual(0, parser.sequenceNumber)
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
            XCTAssertEqual(0, parser.sequenceNumber)
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithExtraLines() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xxxx\r\nyyyy\r\nSSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.9\r\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "xxxx\r\nyyyy\r\nSSH-2.0-OpenSSH_7.9")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithoutCarriageReturn() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "SSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.4\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.4")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithExtraLinesWithoutCarriageReturn() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xxxx\nyyyy\nSSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.4\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "xxxx\nyyyy\nSSH-2.0-OpenSSH_7.4")
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
        XCTAssertEqual(0, parser.sequenceNumber)

        var part2 = ByteBuffer.of(bytes: [28])
        parser.append(bytes: &part2)

        XCTAssertNil(try parser.nextPacket())
        XCTAssertEqual(0, parser.sequenceNumber)

        var part3 = ByteBuffer.of(bytes: [10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97])
        parser.append(bytes: &part3)
        XCTAssertNil(try parser.nextPacket())
        XCTAssertEqual(0, parser.sequenceNumber)

        var part4 = ByteBuffer.of(bytes: [117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])
        parser.append(bytes: &part4)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(1, parser.sequenceNumber)
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
            XCTAssertEqual(1, parser.sequenceNumber)
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
            XCTAssertEqual(1, parser.sequenceNumber)
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(2, parser.sequenceNumber)
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

    func testSequencePreservedBetweenPlainAndCypher() throws {
        let allocator = ByteBufferAllocator()
        var parser = SSHPacketParser(allocator: allocator)
        self.feedVersion(to: &parser)

        var part = ByteBuffer(bytes: [0, 0, 0, 12, 10, 21, 41, 114, 125, 250, 3, 79, 3, 217, 166, 136])
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .newKeys:
            XCTAssertEqual(1, parser.sequenceNumber)
        default:
            XCTFail("Expecting .newKeys")
        }

        part = ByteBuffer(bytes: [0, 0, 0, 12, 10, 21, 41, 114, 125, 250, 3, 79, 3, 217, 166, 136])
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .newKeys:
            XCTAssertEqual(2, parser.sequenceNumber)
        default:
            XCTFail("Expecting .newKeys")
        }

        let inboundEncryptionKey = SymmetricKey(size: .bits128)
        let outboundEncryptionKey = inboundEncryptionKey
        let inboundMACKey = SymmetricKey(size: .bits128)
        let outboundMACKey = inboundMACKey
        let protection = TestTransportProtection(initialKeys: .init(
            initialInboundIV: [],
            initialOutboundIV: [],
            inboundEncryptionKey: inboundEncryptionKey,
            outboundEncryptionKey: outboundEncryptionKey,
            inboundMACKey: inboundMACKey,
            outboundMACKey: outboundMACKey
        ))
        parser.addEncryption(protection)

        part = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try protection.encryptPacket(NIOSSHEncryptablePayload(message: .newKeys), sequenceNumber: 2, to: &part))
        var subpart = part.readSlice(length: 2)!
        parser.append(bytes: &subpart)

        XCTAssertNil(try parser.nextPacket())
        XCTAssertEqual(2, parser.sequenceNumber)

        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .newKeys:
            XCTAssertEqual(3, parser.sequenceNumber)
        default:
            XCTFail("Expecting .newKeys")
        }

        part = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try protection.encryptPacket(NIOSSHEncryptablePayload(message: .newKeys), sequenceNumber: 2, to: &part))
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .newKeys:
            XCTAssertEqual(4, parser.sequenceNumber)
        default:
            XCTFail("Expecting .newKeys")
        }
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
