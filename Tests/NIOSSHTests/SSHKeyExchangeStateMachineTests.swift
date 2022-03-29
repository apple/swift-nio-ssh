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
import NIOEmbedded
@testable import NIOSSH
import XCTest

final class SSHKeyExchangeStateMachineTests: XCTestCase {
    enum AssertionFailure: Error {
        case invalidMessageType
        case unexpectedMultipleMessages
        case unexpectedMissingMessage
    }

    private func assertGeneratesKeyExchangeMessage(_ messageFactory: @autoclosure () throws -> SSHMultiMessage?) throws -> SSHMessage.KeyExchangeMessage {
        guard let message = try assertNoThrowWithValue(messageFactory()) else {
            XCTFail("Unexpected missing message")
            throw AssertionFailure.unexpectedMissingMessage
        }

        guard message.count == 1 else {
            XCTFail("Unexpected multiple message (found \(message.count))")
            throw AssertionFailure.unexpectedMultipleMessages
        }

        guard case .some(.keyExchange(let v)) = message.first else {
            XCTFail("Unexpected message type: \(message)")
            throw AssertionFailure.invalidMessageType
        }

        return v
    }

    private func assertGeneratesNoMessage(_ messageFactory: @autoclosure () throws -> SSHMultiMessage?) throws {
        let message = try assertNoThrowWithValue(messageFactory())

        guard message == nil else {
            XCTFail("Unexpected message type: \(String(describing: message))")
            throw AssertionFailure.invalidMessageType
        }
    }

    private func assertGeneratesECDHKeyExchangeInit(_ messageFactory: @autoclosure () throws -> SSHMultiMessage?) throws -> SSHMessage.KeyExchangeECDHInitMessage {
        guard let message = try assertNoThrowWithValue(messageFactory()) else {
            XCTFail("Unexpected missing message")
            throw AssertionFailure.unexpectedMissingMessage
        }

        guard message.count == 1 else {
            XCTFail("Unexpected multiple message (found \(message.count))")
            throw AssertionFailure.unexpectedMultipleMessages
        }

        guard case .some(.keyExchangeInit(let v)) = message.first else {
            XCTFail("Unexpected message type: \(String(describing: message))")
            throw AssertionFailure.invalidMessageType
        }

        return v
    }

    private func assertGeneratesECDHKeyExchangeReplyAndNewKeys(_ messageFactory: @autoclosure () throws -> SSHMultiMessage?) throws -> SSHMessage.KeyExchangeECDHReplyMessage {
        guard let message = try assertNoThrowWithValue(messageFactory()) else {
            XCTFail("Unexpected missing message")
            throw AssertionFailure.unexpectedMissingMessage
        }

        guard message.count == 2 else {
            XCTFail("Unexpected message count (found \(message.count))")
            throw AssertionFailure.unexpectedMultipleMessages
        }

        guard case .some(.keyExchangeReply(let v)) = message.first else {
            XCTFail("Unexpected message type: \(String(describing: message))")
            throw AssertionFailure.invalidMessageType
        }

        guard case .some(.newKeys) = message.dropFirst().first else {
            XCTFail("Unexpected message type: \(String(describing: message))")
            throw AssertionFailure.invalidMessageType
        }

        return v
    }

    private func assertGeneratesNewKeys(_ messageFactory: @autoclosure () throws -> SSHMultiMessage?) throws {
        guard let message = try assertNoThrowWithValue(messageFactory()) else {
            XCTFail("Unexpected missing message")
            throw AssertionFailure.unexpectedMissingMessage
        }

        guard message.count == 1 else {
            XCTFail("Unexpected multiple message (found \(message.count))")
            throw AssertionFailure.unexpectedMultipleMessages
        }

        guard case .some(.newKeys) = message.first else {
            XCTFail("Unexpected message type: \(String(describing: message))")
            throw AssertionFailure.invalidMessageType
        }
    }

    private func assertGeneratesNewKeysSynchronously(_ messageFactory: @autoclosure () throws -> EventLoopFuture<SSHMultiMessage?>) throws {
        let future = try assertNoThrowWithValue(messageFactory())

        guard let message = try assertNoThrowWithValue(future.wait()) else {
            XCTFail("Unexpected missing message")
            throw AssertionFailure.unexpectedMissingMessage
        }

        guard message.count == 1 else {
            XCTFail("Unexpected multiple message (found \(message.count))")
            throw AssertionFailure.unexpectedMultipleMessages
        }

        guard case .some(.newKeys) = message.first else {
            XCTFail("Unexpected message type: \(String(describing: message))")
            throw AssertionFailure.invalidMessageType
        }
    }

    private func assertUnexpectedMessage<T>(file: StaticString = #file, line: UInt = #line, _ messageFactory: () throws -> T) {
        XCTAssertThrowsError(try messageFactory(), file: file, line: line) { error in
            XCTAssertEqual(error as? SSHKeyExchangeStateMachine.SSHKeyExchangeError, SSHKeyExchangeStateMachine.SSHKeyExchangeError.unexpectedMessage, file: file, line: line)
        }
    }

    private func assertCompatibleProtection(client: NIOSSHTransportProtection, server: NIOSSHTransportProtection) {
        // To assert that the protection is compatible we encrypt a message with one and decrypt with the other, and vice versa.
        let message = SSHMessage.channelRequest(.init(recipientChannel: 1, type: .exec("uname"), wantReply: false))
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)

        do {
            try client.encryptPacket(.init(message: message), to: &buffer)
            try server.decryptFirstBlock(&buffer)
            var messageBuffer = try server.decryptAndVerifyRemainingPacket(&buffer)
            let decrypted = try messageBuffer.readSSHMessage()
            XCTAssertEqual(message, decrypted)
            XCTAssertEqual(0, buffer.readableBytes)
        } catch {
            XCTFail("Unexpected error client to server: \(error)")
            return
        }

        buffer.clear()

        do {
            try server.encryptPacket(.init(message: message), to: &buffer)
            try client.decryptFirstBlock(&buffer)
            var messageBuffer = try client.decryptAndVerifyRemainingPacket(&buffer)
            let decrypted = try messageBuffer.readSSHMessage()
            XCTAssertEqual(message, decrypted)
            XCTAssertEqual(0, buffer.readableBytes)
        } catch {
            XCTFail("Unexpected error server to client: \(error)")
            return
        }
    }

    struct HandshakeStages: OptionSet {
        var rawValue: UInt16

        init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        static let beforeReceiveKeyExchangeClient = HandshakeStages(rawValue: 1 << 0)
        static let beforeReceiveKeyExchangeServer = HandshakeStages(rawValue: 1 << 1)
        static let beforeReceiveKeyExchangeInitServer = HandshakeStages(rawValue: 1 << 2)
        static let beforeSendingKeyExchangeInitClient = HandshakeStages(rawValue: 1 << 3)
        static let beforeReceiveKeyExchangeReplyClient = HandshakeStages(rawValue: 1 << 4)
        static let beforeSendingKeyExchangeReplyServer = HandshakeStages(rawValue: 1 << 5)
        static let beforeSendingNewKeysClient = HandshakeStages(rawValue: 1 << 6)
        static let beforeSendingNewKeysServer = HandshakeStages(rawValue: 1 << 7)
        static let beforeReceiveNewKeysClient = HandshakeStages(rawValue: 1 << 8)
        static let beforeReceiveNewKeysServer = HandshakeStages(rawValue: 1 << 9)
        static let afterCompleteClient = HandshakeStages(rawValue: 1 << 10)
        static let afterCompleteServer = HandshakeStages(rawValue: 1 << 11)
    }

    /// This function runs a full key exchange, in between each step sending the given message to both
    /// client and server, and asserts it always fails.
    private func assertSendingExtraMessageFails(message: SSHMessage, allowedStages: HandshakeStages) throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveKeyExchangeClient, stateMachine: &client)
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveKeyExchangeServer, stateMachine: &server)

        // The server does not generate a response message, but the client does.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveKeyExchangeInitServer, stateMachine: &server)

        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeSendingKeyExchangeInitClient, stateMachine: &client)
        client.send(keyExchangeInit: ecdhInit)
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveKeyExchangeReplyClient, stateMachine: &client)

        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeSendingKeyExchangeReplyServer, stateMachine: &server)
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeSendingNewKeysServer, stateMachine: &server)
        let serverOutboundProtection = server.sendNewKeys()
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveNewKeysServer, stateMachine: &server)

        // Now the client receives the reply, and generates a newKeys message.
        try self.assertGeneratesNewKeysSynchronously(client.handle(keyExchangeReply: ecdhReply))
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeSendingNewKeysClient, stateMachine: &client)
        let clientOutboundProtection = client.sendNewKeys()
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveNewKeysClient, stateMachine: &client)

        // Both peers receive the newKeys messages.
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .afterCompleteClient, stateMachine: &client)
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .afterCompleteServer, stateMachine: &server)

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        self.assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
    }

    func testKeyExchange() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))
        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        let serverOutboundProtection = server.sendNewKeys()

        // Now the client receives the reply, and generates a newKeys message.
        try self.assertGeneratesNewKeysSynchronously(client.handle(keyExchangeReply: ecdhReply))
        let clientOutboundProtection = client.sendNewKeys()

        // Both peers receive the newKeys messages.
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        self.assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
    }

    func testKeyExchangeWithInvalidGuess() throws {
        // This test verifies that the server will tolerate an invalid guessed negotiation. For this reason we only drive a server,
        // as our code never actually guesses.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var server = SSHKeyExchangeStateMachine(allocator: allocator,
                                                loop: loop,
                                                role: .server(.init(hostKeys: [.init(ed25519Key: .init())],
                                                                    userAuthDelegate: DenyAllServerAuthDelegate())),
                                                remoteVersion: Constants.version,
                                                protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
                                                previousSessionIdentifier: nil)

        // Server generates a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)

        // Client sends a key exchange that is _subtly_ different from the server (we just add a different key exchange mechanism to the front).
        // Annoyingly we have to offer an elliptic curve protocol to make sure it parses properly. We use P-192 as the curve, referred to by OID,
        // because we're clearly never going to support that curve. Then we do Curve25519 as the fallback because it's easy.
        var clientMessage = serverMessage
        clientMessage.keyExchangeAlgorithms = ["ecdsa-sha2-1.2.840.10045.3.1.1", "curve25519-sha256"]
        clientMessage.firstKexPacketFollows = true
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))

        // The server should now tolerate a guess for an invalid message. We shouldn't read it, so the fact that it's invalid is irrelevant.
        let message = SSHMessage.KeyExchangeECDHInitMessage(publicKey: allocator.buffer(capacity: 1024))
        try self.assertGeneratesNoMessage(server.handle(keyExchangeInit: message))

        // Now the server wants the correct message. To do that we need a key. It's just 32 random bytes, so let's use 4 pre-chosen 64-bit integers.
        var keyBuffer = allocator.buffer(capacity: 32)
        keyBuffer.writeInteger(UInt64(0x0102_0304_0506_0708))
        keyBuffer.writeInteger(UInt64(0x090A_0B0C_0D0E_0F10))
        keyBuffer.writeInteger(UInt64(0x1112_1314_1516_1718))
        keyBuffer.writeInteger(UInt64(0x191A_1B1C_1D1E_1F20))
        let realMessage = SSHMessage.KeyExchangeECDHInitMessage(publicKey: keyBuffer)

        let response = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: realMessage))
        XCTAssertNoThrow(try server.send(keyExchangeReply: response))
        _ = server.sendNewKeys()
    }

    func testExtraKeyExchangeMessagesAreForbidden() throws {
        // This test verifies that the state machine forbids extra key exchange messages.
        // We get the key exchange message out of the server because it's a pain to build by hand.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        let server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        let serverMessage = server.createKeyExchangeMessage()
        try self.assertSendingExtraMessageFails(message: SSHMessage.keyExchange(serverMessage), allowedStages: [.beforeReceiveKeyExchangeClient, .beforeReceiveKeyExchangeServer])
    }

    func testExtraECDHInitForbidden() throws {
        try self.assertSendingExtraMessageFails(message: SSHMessage.keyExchangeInit(.init(publicKey: ByteBufferAllocator().buffer(capacity: 1024))), allowedStages: [.beforeReceiveKeyExchangeInitServer])
    }

    func testExtraECDHReplyForbidden() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let message = SSHMessage.keyExchangeReply(.init(hostKey: .init(backingKey: .ed25519(privateKey.publicKey)), publicKey: ByteBufferAllocator().buffer(capacity: 1024), signature: .init(backingSignature: .ed25519(.byteBuffer(ByteBufferAllocator().buffer(capacity: 1024))))))
        try self.assertSendingExtraMessageFails(message: message, allowedStages: .beforeReceiveKeyExchangeReplyClient)
    }

    func testExtraNewKeysMessageForbidden() throws {
        try self.assertSendingExtraMessageFails(message: SSHMessage.newKeys, allowedStages: [.beforeSendingNewKeysClient, .beforeSendingNewKeysServer, .beforeReceiveNewKeysClient, .beforeReceiveNewKeysServer])
    }

    func testKeyExchangeRapidNewKeys() throws {
        // This test runs a full key exchange but the server races its newKeys message right behind the ecdh reply.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))

        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        let serverOutboundProtection = server.sendNewKeys()

        // Now the client receives the reply and newKeys, and generates a newKeys message.
        try self.assertGeneratesNewKeysSynchronously(client.handle(keyExchangeReply: ecdhReply))
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        let clientOutboundProtection = client.sendNewKeys()

        // Server receives the newKeys.
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        self.assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
    }

    func testKeyExchangeUsingP256HostKeysOnly() throws {
        try self.straightforwardCustomHostKeyHandshake(hostKey: .init(p256Key: .init()))
    }

    func testKeyExchangeUsingP384HostKeysOnly() throws {
        try self.straightforwardCustomHostKeyHandshake(hostKey: .init(p384Key: .init()))
    }

    func testKeyExchangeUsingP521HostKeysOnly() throws {
        try self.straightforwardCustomHostKeyHandshake(hostKey: .init(p521Key: .init()))
    }

    private func straightforwardCustomHostKeyHandshake(hostKey: NIOSSHPrivateKey) throws {
        // This test runs a full key exchange but the server races its newKeys message right behind the ecdh reply.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [hostKey], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))

        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        let serverOutboundProtection = server.sendNewKeys()

        // Now the client receives the reply and newKeys, and generates a newKeys message.
        try self.assertGeneratesNewKeysSynchronously(client.handle(keyExchangeReply: ecdhReply))
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        let clientOutboundProtection = client.sendNewKeys()

        // Server receives the newKeys.
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        self.assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
    }

    func testKeyExchangeMessageCookieValidation() throws {
        let loop = EmbeddedEventLoop()
        var cookies: [ByteBuffer] = []
        for _ in 0 ..< 5 {
            let allocator = ByteBufferAllocator()
            let client = SSHKeyExchangeStateMachine(
                allocator: allocator,
                loop: loop,
                role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
                remoteVersion: Constants.version,
                protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
                previousSessionIdentifier: nil
            )
            let clientMessage = client.createKeyExchangeMessage()
            cookies.append(clientMessage.cookie)
        }

        XCTAssertTrue(cookies.allSatisfy { $0.readableBytes == 16 })

        // It's hard to validate that cookies are truly random, so what we'll do instead is validate that they are all _different_.
        // That should be good enough: it's statistically stunningly unlikely that we'll generate two identical 16 byte sequences.
        for element in cookies {
            XCTAssertEqual(cookies.filter { $0 == element }.count, 1)
        }
    }

    func testNonOverlappingTransportProtectionFails() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        // Client only supports AES 256, server only supports AES 128. Doomed to failure.
        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES128GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // When the server gets the client's message, it's an error.
        XCTAssertThrowsError(try server.handle(keyExchange: clientMessage)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyExchangeNegotiationFailure)
        }

        // The same happens when the client receives the server's.
        XCTAssertThrowsError(try client.handle(keyExchange: serverMessage)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyExchangeNegotiationFailure)
        }
    }

    func testWeNegotiateTheClientsFirstPreference() throws {
        // Happy path key exchange test, but where the client would prefer AES128 and the server would prefer AES256.
        // We expect AES128, but the negotiation should be smooth.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES128GCMOpenSSHTransportProtection.self, AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self, AES128GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))
        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        let serverOutboundProtection = server.sendNewKeys()

        // Now the client receives the reply, and generates a newKeys message.
        try self.assertGeneratesNewKeysSynchronously(client.handle(keyExchangeReply: ecdhReply))
        let clientOutboundProtection = client.sendNewKeys()

        // Both peers receive the newKeys messages.
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        self.assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
        XCTAssertTrue(clientInboundProtection is AES128GCMOpenSSHTransportProtection)
    }

    func testWeCanReExchangeKeysClientInitiates() throws {
        // This tests the specific message flow for re-exchange: namely, a key exchange message arrives in idle.
        // We should tolerate this flow.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES128GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES128GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Here only the client generates a key exchange message.
        let clientMessage = client.createKeyExchangeMessage()
        client.send(keyExchange: clientMessage)

        // The server generates a key exchange message in response.
        let serverMessage = try self.assertGeneratesKeyExchangeMessage(server.handle(keyExchange: clientMessage))
        server.send(keyExchange: serverMessage)
        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // From here on, the flow is the same as in the regular key exchange.
        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        let serverOutboundProtection = server.sendNewKeys()

        // Now the client receives the reply, and generates a newKeys message.
        try self.assertGeneratesNewKeysSynchronously(client.handle(keyExchangeReply: ecdhReply))
        let clientOutboundProtection = client.sendNewKeys()

        // Both peers receive the newKeys messages.
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        self.assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
        XCTAssertTrue(clientInboundProtection is AES128GCMOpenSSHTransportProtection)
    }

    func testWeCanReExchangeKeysServerInitiates() throws {
        // This tests the specific message flow for re-exchange: namely, a key exchange message arrives in idle.
        // We should tolerate this flow.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES128GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES128GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Here only the server generates a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)

        // The client generates both a key exchange message and a ecdh key exchange init message.
        guard let clientMessages = try client.handle(keyExchange: serverMessage) else {
            XCTFail("Client didn't generate messages")
            return
        }
        guard let firstClientMessage = clientMessages.first, let secondClientMessage = clientMessages.dropFirst().first else {
            XCTFail("Unexpected number of client messages: \(clientMessages)")
            return
        }
        let clientInitMessage = try self.assertGeneratesKeyExchangeMessage(SSHMultiMessage(firstClientMessage))
        let clientEcdhInitMessage = try self.assertGeneratesECDHKeyExchangeInit(SSHMultiMessage(secondClientMessage))
        client.send(keyExchange: clientInitMessage)
        client.send(keyExchangeInit: clientEcdhInitMessage)

        // The server now receives these messages.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientInitMessage))

        // From here on, the flow is the same as in the regular key exchange.
        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: clientEcdhInitMessage))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        let serverOutboundProtection = server.sendNewKeys()

        // Now the client receives the reply, and generates a newKeys message.
        try self.assertGeneratesNewKeysSynchronously(client.handle(keyExchangeReply: ecdhReply))
        let clientOutboundProtection = client.sendNewKeys()

        // Both peers receive the newKeys messages.
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        self.assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
        XCTAssertTrue(clientInboundProtection is AES128GCMOpenSSHTransportProtection)
    }

    func testKeyExchangeDifferentPriorityBetweenServerAndClient() throws {
        // This test runs a full key exchange where the server's host keys are in a different order to the client.
        // This flushes out a bug where we'd choose the wrong host key algorithm because we preferred our own list in
        // all cases, rather than iterating the client's.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var keys = [NIOSSHPrivateKey(p256Key: .init()), NIOSSHPrivateKey(ed25519Key: .init())]

        let serverKeyAlgorithms = keys.flatMap { $0.hostKeyAlgorithms }
        XCTAssertEqual(serverKeyAlgorithms.count, 2)
        let clientKeyAlgorithms = SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms.filter { serverKeyAlgorithms.contains($0) }
        XCTAssertEqual(clientKeyAlgorithms.count, 2)

        // We force these out of order so that there's no way they agree.
        if serverKeyAlgorithms.first == clientKeyAlgorithms.first {
            keys.swapAt(0, 1)
        }

        // From here on, things should run smoothly.
        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: keys, userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))

        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        let serverOutboundProtection = server.sendNewKeys()

        // At this time, both parties have negotiated the algorithm in question, so we check it here. This should be
        // the one that was _last_ in the server' list.
        XCTAssertEqual(client._testOnly_negotiatedHostKeyAlgorithm, server._testOnly_negotiatedHostKeyAlgorithm)
        XCTAssertEqual(client._testOnly_negotiatedHostKeyAlgorithm, keys.last.flatMap { $0.hostKeyAlgorithms.first })

        // Now the client receives the reply and newKeys, and generates a newKeys message.
        try self.assertGeneratesNewKeysSynchronously(client.handle(keyExchangeReply: ecdhReply))
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        let clientOutboundProtection = client.sendNewKeys()

        // Server receives the newKeys.
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        self.assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
    }

    func testKeyExchangeServerReturnsWrongHostKeyType() throws {
        // This test runs a full key exchange where the server returns a host key type it didn't negotiate. This should
        // error.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [NIOSSHPrivateKey(p256Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))

        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply. We ignore newKeys here as we
        // won't get that far.
        var ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))

        // We tweak the reply. This would lead to an invalid signature, but we expect it to be tripped up on
        // the wrong negotiation first.
        ecdhReply.hostKey = NIOSSHPrivateKey(ed25519Key: .init()).publicKey

        // Now the client receives the reply and errors.
        XCTAssertThrowsError(try client.handle(keyExchangeReply: ecdhReply)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidHostKeyForKeyExchange)
        }
    }

    func testKeyExchangeClientRejectsHostKeySynchronously() throws {
        // This test runs a full key exchange where the client rejects the server's host key. This should
        // error.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        enum TestError: Error {
            case bang
        }

        struct RejectHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                validationCompletePromise.fail(TestError.bang)
            }
        }

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: RejectHostKeyDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [NIOSSHPrivateKey(p256Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))

        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply. We ignore newKeys here as we
        // won't get that far.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))

        // Now the client receives the reply. A future is generated.
        let response = try assertNoThrowWithValue(client.handle(keyExchangeReply: ecdhReply))

        // This future will error.
        XCTAssertThrowsError(try response.wait()) { error in
            XCTAssertEqual(error as? TestError, .bang)
        }
    }

    func testKeyExchangeClientRejectsHostKeyAsynchronously() throws {
        // This test runs a full key exchange where the client rejects the server's host key, on a delay. This should
        // error.
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        enum TestError: Error {
            case bang
        }

        class DelayHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
            var data: (NIOSSHPublicKey, EventLoopPromise<Void>)?

            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                self.data = (hostKey, validationCompletePromise)
            }
        }

        let hostKeyDelegate = DelayHostKeyDelegate()
        let serverHostKey = NIOSSHPrivateKey(p256Key: .init())

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: hostKeyDelegate)),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [serverHostKey], userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        // Both sides begin by generating a key exchange message.
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try self.assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))

        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply. We ignore newKeys here as we
        // won't get that far.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReplyAndNewKeys(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))

        // Now the client receives the reply. A future is generated.
        let response = try assertNoThrowWithValue(client.handle(keyExchangeReply: ecdhReply))

        // This future has not completed yet.
        var completed = false
        response.whenComplete { result in
            switch result {
            case .success:
                XCTFail("Unexpected success")
            case .failure(let error):
                XCTAssertEqual(error as? TestError, .bang)
            }
            completed = true
        }
        XCTAssertFalse(completed)

        // The host key we gave the delegate matches the one we got.
        guard let (hostKey, promise) = hostKeyDelegate.data else {
            XCTFail("Host key delegate was not invoked")
            return
        }

        XCTAssertEqual(hostKey, serverHostKey.publicKey)
        XCTAssertFalse(completed)

        // Fail the promise.
        promise.fail(TestError.bang)
        XCTAssertTrue(completed)
    }
}

extension SSHKeyExchangeStateMachineTests {
    /// A simple function that passes a message to the state machine and erases the return value.
    fileprivate func handleUnexpectedMessageErasingValue(_ message: SSHMessage,
                                                         allowedStages: SSHKeyExchangeStateMachineTests.HandshakeStages,
                                                         currentStage: SSHKeyExchangeStateMachineTests.HandshakeStages,
                                                         stateMachine: inout SSHKeyExchangeStateMachine,
                                                         file: StaticString = #file,
                                                         line: UInt = #line) throws {
        if allowedStages.contains(currentStage) {
            // If this stage is allowed, don't try to send the message. Assume it's covered in the mainline.
            return
        }

        self.assertUnexpectedMessage(file: file, line: line) {
            switch message {
            case .keyExchange(let kex):
                _ = try stateMachine.handle(keyExchange: kex)
            case .keyExchangeInit(let kexInit):
                _ = try stateMachine.handle(keyExchangeInit: kexInit)
            case .keyExchangeReply(let kexReply):
                _ = try stateMachine.handle(keyExchangeReply: kexReply)
            case .newKeys:
                _ = try stateMachine.handleNewKeys()
            default:
                preconditionFailure("Unexpected message for testing: \(message)")
            }
        }
    }
}
