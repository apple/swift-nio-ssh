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
import XCTest

@testable import NIOSSH

final class SSHPacketParserTests: XCTestCase {
    /// Feed the SSH version to a packet parser and verify the output.
    ///
    /// Usually used to set up an appropriate state.
    private func feedVersion(to parser: inout SSHPacketParser, file: StaticString = #filePath, line: UInt = #line) {
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
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

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

    func feedBannerString(
        to parser: inout SSHPacketParser,
        ofLength length: Int,
        withSSHPrefix: Bool,
        withCR: Bool,
        lineConut: Int = 1
    ) {

        var buffer = ByteBufferAllocator().buffer(capacity: length)

        var middlePartLength = length - 1  // minus one for LF
        if withSSHPrefix {
            middlePartLength -= 4  // "SSH-"
            buffer.writeString("SSH-")
        }
        if withCR {
            middlePartLength -= 1
        }

        // Append the lines.
        for _ in 0..<lineConut {
            buffer.writeBytes(Array(repeating: UInt8(ascii: "A"), count: middlePartLength))

            if withCR {
                buffer.writeString("\r\n")
            } else {
                buffer.writeString("\n")
            }
        }

        parser.append(bytes: &buffer)
    }

    // RFC 4253 §4.2 caps the identification string:
    // > The maximum length of the string is 255 characters, including the
    // > Carriage Return and Line Feed.
    func testAcceptsUpTo255BytesOfIdentificationServer() throws {
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumVersionStringLength,
            withSSHPrefix: true,
            withCR: false
        )

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(0, parser.sequenceNumber)
            XCTAssert(string.starts(with: "SSH-"))
            XCTAssertEqual(string.count, SSHPacketParser.maximumVersionStringLength - 1)  // line feed
        default:
            XCTFail("Expecting .version")
        }
    }

    func testAcceptsUpTo255BytesOfIdentificationWithCRLFServer() throws {
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumVersionStringLength,
            withSSHPrefix: true,
            withCR: true
        )

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(0, parser.sequenceNumber)
            XCTAssert(string.starts(with: "SSH-"))
            XCTAssertEqual(string.count, SSHPacketParser.maximumVersionStringLength - 2)  // CR, LF
        default:
            XCTFail("Expecting .version")
        }
    }

    func testRejects256BytesOfIdentificationServer() throws {
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumVersionStringLength + 1,
            withSSHPrefix: true,
            withCR: false
        )

        XCTAssertThrowsError(try parser.nextPacket())
    }

    func testRejects256BytesOfIdentificationWithCRLFServer() throws {
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumVersionStringLength + 1,
            withSSHPrefix: true,
            withCR: true
        )

        XCTAssertThrowsError(try parser.nextPacket())
    }

    func testAcceptsUpTo255BytesOfIdentificationClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumVersionStringLength,
            withSSHPrefix: true,
            withCR: false
        )

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(0, parser.sequenceNumber)
            XCTAssert(string.starts(with: "SSH-"))
            XCTAssertEqual(string.count, SSHPacketParser.maximumVersionStringLength - 1)  // line feed
        default:
            XCTFail("Expecting .version")
        }
    }

    func testAcceptsUpTo255BytesOfIdentificationWithCRLFClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumVersionStringLength,
            withSSHPrefix: true,
            withCR: true
        )

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(0, parser.sequenceNumber)
            XCTAssert(string.starts(with: "SSH-"))
            XCTAssertEqual(string.count, SSHPacketParser.maximumVersionStringLength - 2)  // CR, LF
        default:
            XCTFail("Expecting .version")
        }
    }

    func testRejects256BytesOfIdentificationClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumVersionStringLength + 1,
            withSSHPrefix: true,
            withCR: false
        )

        XCTAssertThrowsError(try parser.nextPacket())
    }

    func testRejects256BytesOfIdentificationWithCRLFClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumVersionStringLength + 1,
            withSSHPrefix: true,
            withCR: true
        )

        XCTAssertThrowsError(try parser.nextPacket())
    }

    // The RFC does not limit the preamble. To avoid peers never sending a '\n' we
    // restrict the maximum non-identification preamble length.
    func testAcceptsMaximumLengthPreambleClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumBannerLineLength,
            withSSHPrefix: false,
            withCR: false
        )

        XCTAssertNoThrow(try parser.nextPacket())
    }

    func testAcceptsMultilineMaximumLengthPreambleClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumBannerLineLength,
            withSSHPrefix: false,
            withCR: false,
            lineConut: SSHPacketParser.maximumPreambleLineCount
        )

        XCTAssertNoThrow(try parser.nextPacket())
    }

    func testRejectsOverlongPreambleClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumBannerLineLength + 1,
            withSSHPrefix: false,
            withCR: false
        )

        XCTAssertThrowsError(try parser.nextPacket())
    }

    func testRejectsTooManyLineMultilinePreambleClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        feedBannerString(
            to: &parser,
            ofLength: SSHPacketParser.maximumBannerLineLength,
            withSSHPrefix: false,
            withCR: false,
            lineConut: SSHPacketParser.maximumPreambleLineCount + 1
        )

        XCTAssertThrowsError(try parser.nextPacket())
    }

    func testPlaintextLengthRFCRequiredSize() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        // RFC 4253 §6.1
        // > All implementations MUST be able to process packets with an
        // > uncompressed payload length of 32768 bytes or less and a total packet
        // > size of 35000 bytes or less
        var header = ByteBuffer.of(bytes: [0x00, 0x00, 0x88, 0xB8])
        parser.append(bytes: &header)

        XCTAssertNoThrow(try parser.nextPacket())
    }

    func testPlaintextLengthImplementationMax() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        let size = SSHPacketParser.maximumPlaintextPacketLength
        let bytes = withUnsafeBytes(of: size.bigEndian) {
            Array($0)
        }
        var header = ByteBuffer.of(bytes: bytes)
        parser.append(bytes: &header)

        XCTAssertNoThrow(try parser.nextPacket())
    }

    func testPlaintextLengthImplementationMaxSurpassed() throws {
        guard SSHPacketParser.maximumPlaintextPacketLength < UInt32.max else {
            throw XCTSkip("Limit is already UInt32.max")
        }

        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        let size = SSHPacketParser.maximumPlaintextPacketLength + 1
        let bytes = withUnsafeBytes(of: size.bigEndian) {
            Array($0)
        }
        var header = ByteBuffer.of(bytes: bytes)
        parser.append(bytes: &header)

        XCTAssertThrowsError(try parser.nextPacket())
    }

    func testRejectsOversizedPlaintextLength() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        // 4-byte big-endian length field = 0x10000000 (~268 MB). No body bytes follow,
        // so the test itself allocates nothing large.
        var header = ByteBuffer.of(bytes: [0x10, 0x00, 0x00, 0x00])
        parser.append(bytes: &header)

        XCTAssertThrowsError(try parser.nextPacket())
    }

    // Check that the decrypted packet length (decryptLength) has an upper bound.
    func testRejectsOversizedEncryptedLength() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        // addEncryption is allowed directly from the post-feedVersion .cleartextWaitingForLength state.
        let inboundEncryptionKey = SymmetricKey(size: .bits128)
        let outboundEncryptionKey = inboundEncryptionKey
        let inboundMACKey = SymmetricKey(size: .bits128)
        let outboundMACKey = inboundMACKey
        let protection = TestTransportProtection(
            initialKeys: .init(
                initialInboundIV: [],
                initialOutboundIV: [],
                inboundEncryptionKey: inboundEncryptionKey,
                outboundEncryptionKey: outboundEncryptionKey,
                inboundMACKey: inboundMACKey,
                outboundMACKey: outboundMACKey
            )
        )
        parser.addEncryption(protection)

        // One 128-byte cipher block whose first 4 (big-endian) bytes decode to ~256 MB.
        var plaintextBlock = ByteBufferAllocator().buffer(capacity: 128)
        plaintextBlock.writeInteger(UInt32(0x1000_0000))  // packet length field
        plaintextBlock.writeBytes([UInt8](repeating: 0, count: 124))  // padding

        // Encrypt with the SAME inbound key bytes the protection decrypts with (XOR cipher is symmetric).
        let keyBuffer = inboundEncryptionKey.withUnsafeBytes { ByteBuffer(bytes: $0) }
        var ciphertext = InsecureEncryptionAlgorithm.encrypt(key: keyBuffer, plaintext: plaintextBlock)
        parser.append(bytes: &ciphertext)

        XCTAssertThrowsError(try parser.nextPacket())
    }

    func testEncryptedPacketCapTracksConfiguredMaximumPacketSize() throws {
        func feedFirstBlock(maximumPacketSize: UInt32, injectedPacketSize: UInt32) throws -> SSHMessage? {
            var parser = SSHPacketParser(
                isServer: false,
                allocator: ByteBufferAllocator(),
                maximumPacketSize: maximumPacketSize
            )
            self.feedVersion(to: &parser)

            let inboundEncryptionKey = SymmetricKey(size: .bits128)
            let protection = TestTransportProtection(
                initialKeys: .init(
                    initialInboundIV: [],
                    initialOutboundIV: [],
                    inboundEncryptionKey: inboundEncryptionKey,
                    outboundEncryptionKey: inboundEncryptionKey,
                    inboundMACKey: SymmetricKey(size: .bits128),
                    outboundMACKey: SymmetricKey(size: .bits128)
                )
            )
            parser.addEncryption(protection)

            // One cipher block whose first 4 (big-endian) bytes decode to `length`. We only feed the
            // first block, so once the length is accepted the parser parks waiting for the body.
            var plaintextBlock = ByteBufferAllocator().buffer(capacity: 128)
            plaintextBlock.writeInteger(injectedPacketSize)
            plaintextBlock.writeBytes([UInt8](repeating: 0, count: 124))
            let keyBuffer = inboundEncryptionKey.withUnsafeBytes { ByteBuffer(bytes: $0) }
            var ciphertext = InsecureEncryptionAlgorithm.encrypt(key: keyBuffer, plaintext: plaintextBlock)
            parser.append(bytes: &ciphertext)

            return try parser.nextPacket()
        }

        // Setting the RFC minimum is a valid configuration.
        XCTAssertNoThrow(
            try feedFirstBlock(
                maximumPacketSize: UInt32(Constants.minimumChannelPacketSize),
                injectedPacketSize: UInt32(Constants.minimumChannelPacketSize)
            )
        )

        // The default is greater than the minimum and a packet of its size is not accepted when using the minimum.
        XCTAssertGreaterThan(Constants.defaultMaximumChannelPacketSize, Constants.minimumChannelPacketSize)
        XCTAssertThrowsError(
            try feedFirstBlock(
                maximumPacketSize: UInt32(Constants.minimumChannelPacketSize),
                injectedPacketSize: UInt32(Constants.defaultMaximumChannelPacketSize)
            )
        )

        // The default is also a valid configuration.
        XCTAssertNoThrow(
            try feedFirstBlock(
                maximumPacketSize: UInt32(Constants.defaultMaximumChannelPacketSize),
                injectedPacketSize: UInt32(Constants.defaultMaximumChannelPacketSize)
            )
        )
    }

    func testReadVersionWithExtraLinesOnClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xxxx\r\nyyyy\r\nSSH-2.0-")
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

    func testReadVersionWithExtraLinesOnServer() throws {
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xx")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "xx\r\nyyyy\r\nSSH-2.0-OpenSSH_7.9\r\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "xxxx")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithoutCarriageReturn() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

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

    func testReadVersionWithExtraLinesWithoutCarriageReturnOnClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xxxx\nyyyy\nSSH-2.0-")
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

    func testReadVersionLineFeedFirstByteOnServer() throws {
        // Regression test for the crash described in #237. SSHPacketParser
        // previously accessed `slice[lfIndex.advanced(by: -1)]` without
        // checking that `lfIndex > slice.startIndex`, so a client sending a
        // bare LF as its first byte after the TCP handshake trapped the
        // process. Per the existing server-branch semantics (everything
        // before the first LF is the version line), a leading LF should
        // simply yield an empty version string and not crash.
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "\n")
        parser.append(bytes: &part1)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithExtraLinesWithoutCarriageReturnOnServer() throws {
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xx")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "xx\nyyyy\nSSH-2.0-OpenSSH_7.4\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "xxxx")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testBinaryInParts() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
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
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part1 = ByteBuffer.of(bytes: [
            0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12,
            226, 248, 144, 175, 157, 207,
        ])
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
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part = ByteBuffer.of(bytes: [
            0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12,
            226, 248, 144, 175, 157, 207, 0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97,
            117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207,
        ])
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
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)
        XCTAssertNoThrow(try parser.nextPacket())

        let part = ByteBuffer.of(bytes: [
            0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12,
            226, 248, 144, 175, 157, 207,
        ])

        let neededParts = 2048 / part.readableBytes

        for _ in 0..<neededParts {
            var partCopy = part
            parser.append(bytes: &partCopy)
        }

        // The version field is in the buffer, and we can't really prevent it being there.
        let startingOffset = parser._discardableBytes
        for i in 0..<(neededParts / 2) {
            XCTAssertEqual(parser._discardableBytes, (i * part.readableBytes) + startingOffset)
            XCTAssertNoThrow(try parser.nextPacket())
        }

        // Now we should have cleared up.
        XCTAssertEqual(parser._discardableBytes, 0)
    }

    @available(iOS 13.2, macOS 10.15, watchOS 6.1, tvOS 13.2, *)
    func testSequencePreservedBetweenPlainAndCypher() throws {
        let allocator = ByteBufferAllocator()
        var parser = SSHPacketParser(isServer: false, allocator: allocator)
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
        let protection = TestTransportProtection(
            initialKeys: .init(
                initialInboundIV: [],
                initialOutboundIV: [],
                inboundEncryptionKey: inboundEncryptionKey,
                outboundEncryptionKey: outboundEncryptionKey,
                inboundMACKey: inboundMACKey,
                outboundMACKey: outboundMACKey
            )
        )
        parser.addEncryption(protection)

        part = allocator.buffer(capacity: 1024)
        part.writeSSHPacket(
            message: .newKeys,
            lengthEncrypted: protection.lengthEncrypted,
            blockSize: protection.cipherBlockSize
        )
        XCTAssertNoThrow(try protection.encryptPacket(&part, sequenceNumber: 2))
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
        part.writeSSHPacket(
            message: .newKeys,
            lengthEncrypted: protection.lengthEncrypted,
            blockSize: protection.cipherBlockSize
        )
        XCTAssertNoThrow(try protection.encryptPacket(&part, sequenceNumber: 2))
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
