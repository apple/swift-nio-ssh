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

final class SSHPacketSerializerTests: XCTestCase {
    private func runVersionHandshake(serializer: inout SSHPacketSerializer, parser: inout SSHPacketParser, file: StaticString = #file, line: UInt = #line) {
        var buffer = ByteBufferAllocator().buffer(capacity: 22)
        let versionString = "SSH-2.0-SwiftSSH_1.0"

        XCTAssertNoThrow(try serializer.serialize(message: .version(versionString), to: &buffer), file: file, line: line)
        parser.append(bytes: &buffer)

        var resultingMessage: SSHMessage?
        XCTAssertNoThrow(resultingMessage = try parser.nextPacket(), file: file, line: line)

        switch resultingMessage {
        case .some(.version(let actualVersionString)):
            XCTAssertEqual(versionString, actualVersionString, file: file, line: line)
        default:
            XCTFail("Unexpected message: \(String(describing: resultingMessage))")
        }
    }

    func testVersion() throws {
        let message = SSHMessage.version("SSH-2.0-SwiftSSH_1.0")
        var serializer = SSHPacketSerializer()
        let allocator = ByteBufferAllocator()
        var buffer = allocator.buffer(capacity: 22)
        XCTAssertNoThrow(try serializer.serialize(message: message, to: &buffer))

        XCTAssertEqual("SSH-2.0-SwiftSSH_1.0\r\n", buffer.readString(length: buffer.readableBytes))
    }

    func testDisconnectMessage() throws {
        let message = SSHMessage.disconnect(.init(reason: 42, description: "description", tag: "tag"))
        let allocator = ByteBufferAllocator()
        var serializer = SSHPacketSerializer()
        var parser = SSHPacketParser(allocator: allocator)

        self.runVersionHandshake(serializer: &serializer, parser: &parser)

        var buffer = allocator.buffer(capacity: 20)
        XCTAssertNoThrow(try serializer.serialize(message: message, to: &buffer))
        parser.append(bytes: &buffer)

        switch try parser.nextPacket() {
        case .disconnect(let message):
            XCTAssertEqual(42, message.reason)
            XCTAssertEqual("description", message.description)
            XCTAssertEqual("tag", message.tag)
        default:
            XCTFail("Expecting .disconnect")
        }
    }

    func testServiceRequest() throws {
        let message = SSHMessage.serviceRequest(.init(service: "ssh-userauth"))
        let allocator = ByteBufferAllocator()
        var serializer = SSHPacketSerializer()
        var parser = SSHPacketParser(allocator: allocator)

        self.runVersionHandshake(serializer: &serializer, parser: &parser)

        var buffer = allocator.buffer(capacity: 20)
        XCTAssertNoThrow(try serializer.serialize(message: message, to: &buffer))

        XCTAssertEqual([0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104], buffer.getBytes(at: 0, length: 22))

        parser.append(bytes: &buffer)
        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual("ssh-userauth", message.service)
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testServiceAccept() throws {
        let message = SSHMessage.serviceAccept(.init(service: "ssh-userauth"))
        let allocator = ByteBufferAllocator()
        var serializer = SSHPacketSerializer()
        var parser = SSHPacketParser(allocator: allocator)

        self.runVersionHandshake(serializer: &serializer, parser: &parser)

        var buffer = allocator.buffer(capacity: 20)
        XCTAssertNoThrow(try serializer.serialize(message: message, to: &buffer))

        XCTAssertEqual([0, 0, 0, 28, 10, 6, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104], buffer.getBytes(at: 0, length: 22))

        parser.append(bytes: &buffer)
        switch try parser.nextPacket() {
        case .serviceAccept(let message):
            XCTAssertEqual("ssh-userauth", message.service)
        default:
            XCTFail("Expecting .serviceAccept")
        }
    }

    func testKeyExchange() throws {
        let message = SSHMessage.keyExchange(.init(
            cookie: ByteBuffer.of(bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            keyExchangeAlgorithms: ["curve25519-sha256"],
            serverHostKeyAlgorithms: ["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"],
            encryptionAlgorithmsClientToServer: ["aes256-ctr"],
            encryptionAlgorithmsServerToClient: ["aes256-ctr"],
            macAlgorithmsClientToServer: ["hmac-sha2-256"],
            macAlgorithmsServerToClient: ["hmac-sha2-256"],
            compressionAlgorithmsClientToServer: ["none"],
            compressionAlgorithmsServerToClient: ["none"],
            languagesClientToServer: [],
            languagesServerToClient: [],
            firstKexPacketFollows: false
        ))
        let allocator = ByteBufferAllocator()
        var serializer = SSHPacketSerializer()
        var parser = SSHPacketParser(allocator: allocator)

        self.runVersionHandshake(serializer: &serializer, parser: &parser)

        var buffer = allocator.buffer(capacity: 20)
        XCTAssertNoThrow(try serializer.serialize(message: message, to: &buffer))

        parser.append(bytes: &buffer)
        switch try parser.nextPacket() {
        case .keyExchange(let message):
            XCTAssertEqual(ByteBuffer.of(bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), message.cookie)
            XCTAssertEqual(["curve25519-sha256"], message.keyExchangeAlgorithms)
            XCTAssertEqual(["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"], message.serverHostKeyAlgorithms)
            XCTAssertEqual(["aes256-ctr"], message.encryptionAlgorithmsClientToServer)
            XCTAssertEqual(["aes256-ctr"], message.encryptionAlgorithmsServerToClient)
            XCTAssertEqual(["hmac-sha2-256"], message.macAlgorithmsClientToServer)
            XCTAssertEqual(["hmac-sha2-256"], message.macAlgorithmsServerToClient)
            XCTAssertEqual(["none"], message.compressionAlgorithmsClientToServer)
            XCTAssertEqual(["none"], message.compressionAlgorithmsServerToClient)
            XCTAssertEqual([], message.languagesClientToServer)
            XCTAssertEqual([], message.languagesServerToClient)
            XCTAssertEqual(false, message.firstKexPacketFollows)
        default:
            XCTFail("Expecting .keyExchange")
        }
    }

    func testKeyExchangeInit() throws {
        let message = SSHMessage.keyExchangeInit(.init(publicKey: ByteBuffer.of(bytes: [42])))
        let allocator = ByteBufferAllocator()
        var serializer = SSHPacketSerializer()
        var parser = SSHPacketParser(allocator: allocator)

        self.runVersionHandshake(serializer: &serializer, parser: &parser)

        var buffer = allocator.buffer(capacity: 20)
        XCTAssertNoThrow(try serializer.serialize(message: message, to: &buffer))

        parser.append(bytes: &buffer)
        switch try parser.nextPacket() {
        case .keyExchangeInit(let message):
            XCTAssertEqual(ByteBuffer.of(bytes: [42]), message.publicKey)

        default:
            XCTFail("Expecting .keyExchangeInit")
        }
    }

    func testKeyExchangeReply() throws {
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: [182, 37, 100, 183, 198, 201, 188, 148, 70, 200, 201, 225, 14, 66, 236, 124, 45, 246, 72, 46, 242, 24, 149, 170, 135, 58, 10, 18, 208, 163, 106, 118])
        let signature = Data([18, 95, 167, 169, 241, 132, 161, 143, 58, 35, 228, 10, 66, 187, 185, 176, 60, 95, 53, 188, 238, 226, 202, 75, 45, 226, 101, 39, 51, 168, 2, 92, 211, 28, 235, 229, 200, 249, 234, 71, 231, 245, 198, 167, 222, 207, 11, 151, 144, 218, 148, 205, 15, 77, 69, 72, 201, 37, 125, 94, 227, 173, 194, 10])
        let message = SSHMessage.keyExchangeReply(.init(
            hostKey: NIOSSHPublicKey(backingKey: .ed25519(key)),
            publicKey: ByteBuffer.of(bytes: [42, 42]),
            signature: NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        ))
        let allocator = ByteBufferAllocator()
        var serializer = SSHPacketSerializer()
        var parser = SSHPacketParser(allocator: allocator)

        self.runVersionHandshake(serializer: &serializer, parser: &parser)

        var buffer = allocator.buffer(capacity: 20)
        XCTAssertNoThrow(try serializer.serialize(message: message, to: &buffer))

        parser.append(bytes: &buffer)
        switch try parser.nextPacket() {
        case .keyExchangeReply(let message):
            switch message.hostKey.backingKey {
            case .ed25519(let bytes):
                XCTAssertEqual(key.rawRepresentation, bytes.rawRepresentation)
            default:
                XCTFail("Key is incorrect")
            }
            XCTAssertEqual(ByteBuffer.of(bytes: [42, 42]), message.publicKey)
            switch message.signature.backingSignature {
            case .ed25519(.byteBuffer(let bytes)):
                XCTAssertEqual(signature, Data(bytes.readableBytesView))
            default:
                XCTFail("Signature is incorrect")
            }
        default:
            XCTFail("Expecting .keyExchangeReply")
        }
    }

    func testNewKey() throws {
        let message = SSHMessage.newKeys
        let allocator = ByteBufferAllocator()
        var serializer = SSHPacketSerializer()
        var parser = SSHPacketParser(allocator: allocator)

        self.runVersionHandshake(serializer: &serializer, parser: &parser)

        var buffer = allocator.buffer(capacity: 5)
        XCTAssertNoThrow(try serializer.serialize(message: message, to: &buffer))

        parser.append(bytes: &buffer)
        switch try parser.nextPacket() {
        case .newKeys:
            break
        default:
            XCTFail("Expecting .newKeys")
        }
    }
}
