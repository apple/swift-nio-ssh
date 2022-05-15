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

final class SSHMessagesTests: XCTestCase {
    /// This assertion validates two things: first, that partial-message reads return nil, and
    /// second, that they apporpriately maintain reader indices.
    private func assertCorrectlyManagesPartialRead(_ message: SSHMessage) throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHMessage(message)
        let messageBytes = buffer.readableBytesView[...]
        buffer.clear()

        for byte in messageBytes.dropLast() {
            buffer.writeInteger(byte)
            XCTAssertNil(try buffer.readSSHMessage())
        }

        if let last = messageBytes.last {
            buffer.writeInteger(last)
        }

        XCTAssertEqual(try buffer.readSSHMessage(), message)
    }

    func testDisconnnect() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.disconnect(.init(reason: 2, description: "user closed connection", tag: ""))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.DisconnectMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testIgnore() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        var otherBuffer = ByteBufferAllocator().buffer(capacity: 100)
        otherBuffer.writeString("A string!")
        let message = SSHMessage.ignore(.init(data: otherBuffer))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.IgnoreMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUnimplemented() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.unimplemented(.init(sequenceNumber: 77))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.UnimplementedMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testServiceRequest() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.serviceRequest(.init(service: "ssh-userauth"))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ServiceRequestMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testServiceAccept() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.serviceAccept(.init(service: "ssh-userauth"))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ServiceAcceptMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testKeyExchangeMessage() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.keyExchange(.init(
            cookie: ByteBuffer.of(bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            keyExchangeAlgorithms: [Substring("keyExchange1"), Substring("keyExchange2")],
            serverHostKeyAlgorithms: [Substring("serverHostKeyAlgorithms1"), Substring("serverHostKeyAlgorithms2")],
            encryptionAlgorithmsClientToServer: [Substring("encryptionAlgorithmsClientToServer1"), Substring("encryptionAlgorithmsClientToServer2")],
            encryptionAlgorithmsServerToClient: [Substring("encryptionAlgorithmsServerToClient1"), Substring("encryptionAlgorithmsServerToClient2")],
            macAlgorithmsClientToServer: [Substring("macAlgorithmsClientToServer1"), Substring("macAlgorithmsClientToServer2")],
            macAlgorithmsServerToClient: [Substring("macAlgorithmsServerToClient1"), Substring("macAlgorithmsServerToClient2")],
            compressionAlgorithmsClientToServer: [Substring("compressionAlgorithmsClientToServer1"), Substring("compressionAlgorithmsClientToServer2")],
            compressionAlgorithmsServerToClient: [Substring("compressionAlgorithmsServerToClient1"), Substring("compressionAlgorithmsServerToClient2")],
            languagesClientToServer: [Substring("languagesClientToServer1"), Substring("languagesClientToServer2")],
            languagesServerToClient: [Substring("languagesServerToClient1"), Substring("languagesServerToClient2")],
            firstKexPacketFollows: false
        ))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.KeyExchangeMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testKeyExchangeInit() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.keyExchangeInit(.init(publicKey: ByteBuffer.of(bytes: [42])))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.KeyExchangeECDHInitMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testKeyExchangeReply() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let key = NIOSSHPrivateKey(ed25519Key: .init())
        var digest = SHA256()
        digest.update(data: [24])
        let signature = try key.sign(digest: digest.finalize())
        let message = SSHMessage.keyExchangeReply(.init(hostKey: key.publicKey, publicKey: ByteBuffer.of(bytes: [42]), signature: signature))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.KeyExchangeECDHReplyMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testNewKeys() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.newKeys

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUserAuthRequest() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.userAuthRequest(.init(username: "test", service: "ssh-connection", method: .password("pwd")))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.UserAuthRequestMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUserAuthRequestWithKeysNoSignature() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let key = NIOSSHPrivateKey(ed25519Key: .init())

        let message = SSHMessage.userAuthRequest(.init(username: "test",
                                                       service: "ssh-connection",
                                                       method: .publicKey(.known(key: key.publicKey, signature: nil))))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUserAuthRequestWithKeysAndSignature() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let key = NIOSSHPrivateKey(ed25519Key: .init())
        let signature = try key.sign(digest: SHA256.hash(data: Array("hello world!".utf8)))

        let message = SSHMessage.userAuthRequest(.init(username: "test",
                                                       service: "ssh-connection",
                                                       method: .publicKey(.known(key: key.publicKey, signature: signature))))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUserAuthRequestWithMismatchedKeyAndAlgorithm() throws {
        // This is a SSHMessage.userAuthRequest that has been tweaked to have an ed25519 key claiming to be a P256 key.
        let message: [UInt8] = [
            50, // Type: user auth request
            0, 0, 0, 4, // SSH String: 4 bytes
            116, 101, 115, 116, // username "test"
            0, 0, 0, 14, // SSH string: 14 bytes
            115, 115, 104, 45, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, // Service name: "ssh-connection"
            0, 0, 0, 9, // SSH string: 9 bytes
            112, 117, 98, 108, 105, 99, 107, 101, 121, // Authorization type: "publickey"
            0, // SSH Bool: signature follows = false
            0, 0, 0, 19, // SSH String: 19 bytes
            101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, // public key type: "ecdsa-sha2-nistp256"
            0, 0, 0, 51, // SSH String: 51 bytes
            0, 0, 0, 11, // SSH string: 11 bytes
            115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, // Key type: "ssh-ed25519"
            0, 0, 0, 32, // SSH string: 32 bytes
            118, 208, 190, 118, 231, 217, 30, 99, 140, 250, 52, // raw key bytes
            55, 241, 233, 78, 43, 19, 110, 34, 206, 254, 170,
            38, 226, 210, 30, 134, 86, 144, 252, 193, 188,
        ]

        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        buffer.writeBytes(message)

        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testUserAuthRequestToleratesUnsupportedPublicKeyAlgorithms() throws {
        // This test ensures that userAuthRequest will tolerate an unsupported public key algorithm.
        let message: [UInt8] = [
            50, // Type: user auth request
            0, 0, 0, 4, // SSH String: 4 bytes
            116, 101, 115, 116, // username "test"
            0, 0, 0, 14, // SSH string: 14 bytes
            115, 115, 104, 45, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, // Service name: "ssh-connection"
            0, 0, 0, 9, // SSH string: 9 bytes
            112, 117, 98, 108, 105, 99, 107, 101, 121, // Authorization type: "publickey"
            1, // SSH Bool: signature follows = true
            0, 0, 0, 14, // SSH String: 14 bytes
            110, 111, 116, 45, 97, 45, 114, 101, 97, 108, 45, 107, 101, 121, // public key type: "not-a-real-key"
            0, 0, 0, 50, // SSH String: 50 bytes
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, // gibberish bytes: we shouldn't be parsing them. This is the "key"
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
            36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
            0, 0, 0, 30, // SSH string: 30 bytes
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, // gibberish bytes: this is a "signature"
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        ]

        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        buffer.writeBytes(message)

        let expectedMessage = SSHMessage.userAuthRequest(.init(username: "test", service: "ssh-connection", method: .publicKey(.unknown)))
        XCTAssertEqual(try buffer.readSSHMessage(), expectedMessage)
    }

    func testUserAuthRequestToleratesUnsupportedPublicKeyAlgorithmsWithoutSignatures() throws {
        // This test ensures that userAuthRequest will tolerate an unsupported public key algorithm without a singature.
        let message: [UInt8] = [
            50, // Type: user auth request
            0, 0, 0, 4, // SSH String: 4 bytes
            116, 101, 115, 116, // username "test"
            0, 0, 0, 14, // SSH string: 14 bytes
            115, 115, 104, 45, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, // Service name: "ssh-connection"
            0, 0, 0, 9, // SSH string: 9 bytes
            112, 117, 98, 108, 105, 99, 107, 101, 121, // Authorization type: "publickey"
            0, // SSH Bool: signature follows = false
            0, 0, 0, 14, // SSH String: 14 bytes
            110, 111, 116, 45, 97, 45, 114, 101, 97, 108, 45, 107, 101, 121, // public key type: "not-a-real-key"
            0, 0, 0, 50, // SSH String: 50 bytes
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, // gibberish bytes: we shouldn't be parsing them. This is the "key"
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
            36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
        ]

        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        buffer.writeBytes(message)

        let expectedMessage = SSHMessage.userAuthRequest(.init(username: "test", service: "ssh-connection", method: .publicKey(.unknown)))
        XCTAssertEqual(try buffer.readSSHMessage(), expectedMessage)
    }

    func testUserAuthPKOKP256() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(p256Key: .init())
        let message = SSHMessage.userAuthPKOK(.init(key: key.publicKey))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUserAuthPKOKP384() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(p384Key: .init())
        let message = SSHMessage.userAuthPKOK(.init(key: key.publicKey))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUserAuthPKOKP521() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(p521Key: .init())
        let message = SSHMessage.userAuthPKOK(.init(key: key.publicKey))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUserAuthPKOKWithMismatchedKeyAndAlgorithm() throws {
        // This is a SSHMessage.userAuthPKOK that has been tweaked to have an ed25519 key claiming to be a P256 key.
        let message: [UInt8] = [
            60, // Type: user auth PK OK
            0, 0, 0, 19, // SSH String: 19 bytes
            101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, // public key type: "ecdsa-sha2-nistp256"
            0, 0, 0, 51, // SSH String: 51 bytes
            0, 0, 0, 11, // SSH String: 11 bytes
            115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, // key type: "ssh-ed25519"
            0, 0, 0, 32, // SSH String: 32 bytes
            199, 71, 224, 105, 163, 32, 57, 80, 25, 213, 160, 24, 221, 96, // raw key bytes
            104, 162, 186, 156, 99, 159, 50, 153, 116, 91, 129, 87, 130,
            137, 185, 251, 199, 249,
        ]

        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        buffer.writeBytes(message)

        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testUserAuthPKOKWithUnknownKeyFormat() throws {
        // This is a SSHMessage.userAuthPKOK that has been tweaked to have an unknown key algorithm.
        // We don't tolerate these: they can only be sent to us if we sent a message out for this kind of key,
        // and naturally we never try to use keys we don't understand.
        let message: [UInt8] = [
            60, // Type: user auth PK OK
            0, 0, 0, 14, // SSH String: 14 bytes
            110, 111, 116, 45, 97, 45, 114, 101, 97, 108, 45, 107, 101, 121, // public key type: "not-a-real-key"
            0, 0, 0, 50, // SSH String: 50 bytes
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, // gibberish bytes: we shouldn't be parsing them. This is the "key"
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
            36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
        ]

        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        buffer.writeBytes(message)

        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testUserAuthFailure() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.userAuthFailure(.init(authentications: [Substring("password")], partialSuccess: false))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.UserAuthFailureMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUserAuthSuccess() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.userAuthSuccess

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testUserAuthBanner() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.userAuthBanner(.init(message: "Very important banner message containing crucial legal information.", languageTag: "en"))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.UserAuthBannerMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testGlobalRequest() throws {
        let allocator = ByteBufferAllocator()
        var buffer = allocator.buffer(capacity: 100)
        let message = SSHMessage.globalRequest(.init(wantReply: false, type: .tcpipForward("0.0.0.0", 2222)))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)

        let secondMessage = SSHMessage.globalRequest(.init(wantReply: true, type: .cancelTcpipForward("10.0.0.1", 66)))
        buffer.writeSSHMessage(secondMessage)
        XCTAssertEqual(try buffer.readSSHMessage(), secondMessage)

        try self.assertCorrectlyManagesPartialRead(secondMessage)

        var thirdMessagePayload = allocator.buffer(capacity: 12)
        thirdMessagePayload.writeBytes(Array(randomBytes: 12))

        let thirdMessage = SSHMessage.globalRequest(.init(wantReply: true, type: .unknown("test", thirdMessagePayload)))
        buffer.writeSSHMessage(thirdMessage)
        XCTAssertEqual(try buffer.readSSHMessage(), thirdMessage)

        try self.assertCorrectlyManagesPartialRead(secondMessage)

        buffer.writeBytes([SSHMessage.GlobalRequestMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        buffer.clear()
        buffer.writeBytes([SSHMessage.GlobalRequestMessage.id, 0, 0, 0, 4, UInt8(ascii: "t"), UInt8(ascii: "e"), UInt8(ascii: "s"), UInt8(ascii: "t"), 0])
        XCTAssertNotNil(try buffer.readSSHMessage())
    }

    func testUnknownGlobalRequest() throws {
        // The arbitrary number of 12 has no meaning here
        // What _is_ important is that the amount of added bytes is greater than 0
        // This test verifies that an unknown message will use the remainder of the packet's payload
        let randomPayload = Array(randomBytes: 12)

        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        buffer.writeBytes([SSHMessage.GlobalRequestMessage.id, 0, 0, 0, 4, UInt8(ascii: "t"), UInt8(ascii: "e"), UInt8(ascii: "s"), UInt8(ascii: "t"), 1])
        buffer.writeBytes(randomPayload)

        let unknownMessage = try buffer.readSSHMessage()

        guard case .some(.globalRequest(let globalRequest)) = unknownMessage else {
            XCTFail("SSH message is not a global request")
            return
        }

        XCTAssertTrue(globalRequest.wantReply)

        guard case .unknown(let name, let payload) = globalRequest.type else {
            XCTFail("Decoded global request is not unknown")
            return
        }

        XCTAssertEqual(name, "test")
        XCTAssertEqual(Array(payload.readableBytesView), randomPayload)
    }

    func testChannelOpen() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)

        var message = SSHMessage.channelOpen(.init(type: .session, senderChannel: 0, initialWindowSize: 42, maximumPacketSize: 24))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        try self.assertCorrectlyManagesPartialRead(message)

        let address = try! SocketAddress(ipAddress: "10.0.0.1", port: 443)

        message = SSHMessage.channelOpen(.init(type: .forwardedTCPIP(.init(hostListening: "localhost", portListening: 80, originatorAddress: address)), senderChannel: 0, initialWindowSize: 42, maximumPacketSize: 24))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        try self.assertCorrectlyManagesPartialRead(message)

        message = SSHMessage.channelOpen(.init(type: .directTCPIP(.init(hostToConnectTo: "github.com", portToConnectTo: 443, originatorAddress: address)), senderChannel: 0, initialWindowSize: 42, maximumPacketSize: 24))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        try self.assertCorrectlyManagesPartialRead(message)

        func writeBadMessage(into buffer: inout ByteBuffer, type: String, firstPort: UInt32, secondPort: UInt32) {
            buffer.writeInteger(SSHMessage.ChannelOpenMessage.id)
            buffer.writeSSHString(type.utf8)
            buffer.writeInteger(UInt32(1))
            buffer.writeInteger(UInt32(1))
            buffer.writeInteger(UInt32(1))
            buffer.writeSSHString("::1".utf8)
            buffer.writeInteger(firstPort)
            buffer.writeSSHString("::1".utf8)
            buffer.writeInteger(secondPort)
        }

        buffer.clear()
        writeBadMessage(into: &buffer, type: "forwarded-tcpip", firstPort: 65536, secondPort: 80)
        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unknownPacketType)
        }

        buffer.clear()
        writeBadMessage(into: &buffer, type: "forwarded-tcpip", firstPort: 80, secondPort: 65536)
        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unknownPacketType)
        }

        buffer.clear()
        writeBadMessage(into: &buffer, type: "direct-tcpip", firstPort: 65536, secondPort: 80)
        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unknownPacketType)
        }

        buffer.clear()
        writeBadMessage(into: &buffer, type: "direct-tcpip", firstPort: 80, secondPort: 65536)
        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unknownPacketType)
        }

        buffer.clear()
        buffer.writeBytes([SSHMessage.ChannelOpenMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelOpenConfirmation() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelOpenConfirmation(.init(recipientChannel: 0, senderChannel: 1, initialWindowSize: 42, maximumPacketSize: 24))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelOpenConfirmationMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testChannelOpenFailure() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelOpenFailure(.init(recipientChannel: 0, reasonCode: 1, description: "desc", language: "lang"))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelOpenFailureMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testChannelWindowAdjust() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelWindowAdjust(.init(recipientChannel: 0, bytesToAdd: 42))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelWindowAdjustMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testChannelData() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelData(.init(recipientChannel: 0, data: ByteBuffer.of(string: "hello")))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelDataMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testChannelExtendedData() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelExtendedData(.init(recipientChannel: 0, dataTypeCode: .stderr, data: ByteBuffer.of(string: "hello")))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelExtendedDataMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testChannelEOF() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelEOF(.init(recipientChannel: 0))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelEOFMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testChannelClose() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelClose(.init(recipientChannel: 0))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelCloseMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testChannelRequest() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        var message = SSHMessage.channelRequest(.init(recipientChannel: 0, type: .env("A", "B"), wantReply: true))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        try self.assertCorrectlyManagesPartialRead(message)

        message = SSHMessage.channelRequest(.init(recipientChannel: 0, type: .exec("date"), wantReply: true))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        try self.assertCorrectlyManagesPartialRead(message)

        message = SSHMessage.channelRequest(.init(recipientChannel: 0, type: .exitStatus(1), wantReply: true))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        try self.assertCorrectlyManagesPartialRead(message)

        buffer.writeBytes([SSHMessage.ChannelRequestMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelSuccess() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelSuccess(.init(recipientChannel: 0))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelSuccessMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testChannelFailure() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelFailure(.init(recipientChannel: 0))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelFailureMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testTypeError() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)

        XCTAssertNil(try buffer.readSSHMessage())

        buffer.writeBytes([127])
        XCTAssertThrowsError(try buffer.readSSHMessage())
    }

    func testRequestSuccess() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)

        var message = SSHMessage.requestSuccess(
            .init(.tcpForwarding(.init(boundPort: 6)), allocator: ByteBufferAllocator())
        )
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        message = SSHMessage.requestSuccess(
            .init(.tcpForwarding(.init(boundPort: nil)), allocator: ByteBufferAllocator())
        )
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        // We don't use the partial read test here as it fails: this message is opaque
        // bytes to us, so we tolerate any possible length. We rely on the higher-level framing
        // logic to avoid breakage.
    }

    func testRequestFailure() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.requestFailure

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.clear()
        buffer.writeBytes([SSHMessage.RequestFailureMessage.id])
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)
    }

    func testDebug() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.debug(.init(alwaysDisplay: true, message: "this is a debug message", language: "en-US"))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        try self.assertCorrectlyManagesPartialRead(message)
    }
}
