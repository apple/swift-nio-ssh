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

import XCTest
import NIO
import Crypto
@testable import NIOSSH

final class SSHKeyExchangeStateMachineTests: XCTestCase {
    enum AssertionFailure: Error {
        case invalidMessageType
    }

    private func assertGeneratesKeyExchangeMessage(_ messageFactory: @autoclosure () throws -> SSHMessage) throws -> SSHMessage.KeyExchangeMessage {
        let message = try assertNoThrowWithValue(messageFactory())

        guard case .keyExchange(let v) = message else {
            XCTFail("Unexpected message type: \(message)")
            throw AssertionFailure.invalidMessageType
        }

        return v
    }

    private func assertGeneratesNoMessage(_ messageFactory: @autoclosure () throws -> SSHMessage?) throws {
        let message = try assertNoThrowWithValue(messageFactory())

        guard message == nil else {
            XCTFail("Unexpected message type: \(String(describing: message))")
            throw AssertionFailure.invalidMessageType
        }
    }

    private func assertGeneratesECDHKeyExchangeInit(_ messageFactory: @autoclosure () throws -> SSHMessage?) throws -> SSHMessage.KeyExchangeECDHInitMessage {
        let message = try assertNoThrowWithValue(messageFactory())

        guard case .some(.keyExchangeInit(let v)) = message else {
            XCTFail("Unexpected message type: \(String(describing: message))")
            throw AssertionFailure.invalidMessageType
        }

        return v
    }

    private func assertGeneratesECDHKeyExchangeReply(_ messageFactory: @autoclosure () throws -> SSHMessage?) throws -> SSHMessage.KeyExchangeECDHReplyMessage {
        let message = try assertNoThrowWithValue(messageFactory())

        guard case .some(.keyExchangeReply(let v)) = message else {
            XCTFail("Unexpected message type: \(String(describing: message))")
            throw AssertionFailure.invalidMessageType
        }

        return v
    }

    private func assertGeneratesNewKeys(_ messageFactory: @autoclosure () throws -> SSHMessage?) throws {
        let message = try assertNoThrowWithValue(messageFactory())

        guard case .some(.newKeys) = message else {
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

        static let beforeReceiveKeyExchangeClient      = HandshakeStages(rawValue: 1 << 0)
        static let beforeReceiveKeyExchangeServer      = HandshakeStages(rawValue: 1 << 1)
        static let beforeReceiveKeyExchangeInitServer  = HandshakeStages(rawValue: 1 << 2)
        static let beforeSendingKeyExchangeInitClient  = HandshakeStages(rawValue: 1 << 3)
        static let beforeReceiveKeyExchangeReplyClient = HandshakeStages(rawValue: 1 << 4)
        static let beforeSendingKeyExchangeReplyServer = HandshakeStages(rawValue: 1 << 5)
        static let beforeSendingNewKeysClient          = HandshakeStages(rawValue: 1 << 6)
        static let beforeSendingNewKeysServer          = HandshakeStages(rawValue: 1 << 7)
        static let beforeReceiveNewKeysClient          = HandshakeStages(rawValue: 1 << 8)
        static let beforeReceiveNewKeysServer          = HandshakeStages(rawValue: 1 << 9)
        static let afterCompleteClient                 = HandshakeStages(rawValue: 1 << 10)
        static let afterCompleteServer                 = HandshakeStages(rawValue: 1 << 11)
    }

    /// This function runs a full key exchange, in between each step sending the given message to both
    /// client and server, and asserts it always fails.
    private func assertSendingExtraMessageFails(message: SSHMessage, allowedStages: HandshakeStages) throws {
        let allocator = ByteBufferAllocator()

        var client = SSHKeyExchangeStateMachine(allocator: allocator, role: .client, remoteVersion: Constants.version)
        var server = SSHKeyExchangeStateMachine(allocator: allocator, role: .server(.init(ed25519Key: .init())), remoteVersion: Constants.version)

        // Both sides begin by generating a key exchange message.
        let serverMessage = try assertGeneratesKeyExchangeMessage(server.startKeyExchange())
        let clientMessage = try assertGeneratesKeyExchangeMessage(client.startKeyExchange())
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveKeyExchangeClient, stateMachine: &client)
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveKeyExchangeServer, stateMachine: &server)

        // The server does not generate a response message, but the client does.
        try assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveKeyExchangeInitServer, stateMachine: &server)

        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeSendingKeyExchangeInitClient, stateMachine: &client)
        client.send(keyExchangeInit: ecdhInit)
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveKeyExchangeReplyClient, stateMachine: &client)

        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReply(server.handle(keyExchangeInit: ecdhInit))
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeSendingKeyExchangeReplyServer, stateMachine: &server)
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeSendingNewKeysServer, stateMachine: &server)
        let serverOutboundProtection = server.sendNewKeys()
        try handleUnexpectedMessageErasingValue(message, allowedStages: allowedStages, currentStage: .beforeReceiveNewKeysServer, stateMachine: &server)

        // Now the client receives the reply, and generates a newKeys message.
        try assertGeneratesNewKeys(client.handle(keyExchangeReply: ecdhReply))
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

        assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
    }

    func testKeyExchange() throws {
        let allocator = ByteBufferAllocator()

        var client = SSHKeyExchangeStateMachine(allocator: allocator, role: .client, remoteVersion: Constants.version)
        var server = SSHKeyExchangeStateMachine(allocator: allocator, role: .server(.init(ed25519Key: .init())), remoteVersion: Constants.version)

        // Both sides begin by generating a key exchange message.
        let serverMessage = try assertGeneratesKeyExchangeMessage(server.startKeyExchange())
        let clientMessage = try assertGeneratesKeyExchangeMessage(client.startKeyExchange())
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))
        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReply(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        let serverOutboundProtection = server.sendNewKeys()

        // Now the client receives the reply, and generates a newKeys message.
        try assertGeneratesNewKeys(client.handle(keyExchangeReply: ecdhReply))
        let clientOutboundProtection = client.sendNewKeys()

        // Both peers receive the newKeys messages.
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
    }

    func testKeyExchangeWithInvalidGuess() throws {
        // This test verifies that the server will tolerate an invalid guessed negotiation. For this reason we only drive a server,
        // as our code never actually guesses.
        let allocator = ByteBufferAllocator()
        var server = SSHKeyExchangeStateMachine(allocator: allocator, role: .server(.init(ed25519Key: .init())), remoteVersion: Constants.version)

        // Server generates a key exchange message.
        let serverMessage = try assertGeneratesKeyExchangeMessage(server.startKeyExchange())
        server.send(keyExchange: serverMessage)

        // Client sends a key exchange that is _subtly_ different from the server (we just add a different key exchange mechanism to the front).
        // Annoyingly we have to offer an elliptic curve protocol to make sure it parses properly. We use P-192 as the curve, referred to by OID,
        // because we're clearly never going to support that curve.
        var clientMessage = serverMessage
        clientMessage.keyExchangeAlgorithms = ["ecdsa-sha2-1.2.840.10045.3.1.1"] + serverMessage.keyExchangeAlgorithms
        clientMessage.firstKexPacketFollows = true
        try assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))

        // The server should now tolerate a guess for an invalid message. We shouldn't read it, so the fact that it's invalid is irrelevant.
        let message = SSHMessage.KeyExchangeECDHInitMessage(publicKey: allocator.buffer(capacity: 1024))
        try assertGeneratesNoMessage(server.handle(keyExchangeInit: message))

        // Now the server wants the correct message. To do that we need a key. It's just 32 random bytes, so let's use 4 pre-chosen 64-bit integers.
        var keyBuffer = allocator.buffer(capacity: 32)
        keyBuffer.writeInteger(UInt64(0x0102030405060708))
        keyBuffer.writeInteger(UInt64(0x090a0b0c0d0e0f10))
        keyBuffer.writeInteger(UInt64(0x1112131415161718))
        keyBuffer.writeInteger(UInt64(0x191a1b1c1d1e1f20))
        let realMessage = SSHMessage.KeyExchangeECDHInitMessage(publicKey: keyBuffer)

        let response = try assertGeneratesECDHKeyExchangeReply(server.handle(keyExchangeInit: realMessage))
        XCTAssertNoThrow(try server.send(keyExchangeReply: response))
        _ = server.sendNewKeys()
    }

    func testExtraKeyExchangeMessagesAreForbidden() throws {
        // This test verifies that the state machine forbids extra key exchange messages.
        // We get the key exchange message out of the server because it's a pain to build by hand.
        let allocator = ByteBufferAllocator()
        var server = SSHKeyExchangeStateMachine(allocator: allocator, role: .server(.init(ed25519Key: .init())), remoteVersion: Constants.version)
        let serverMessage = try assertGeneratesKeyExchangeMessage(server.startKeyExchange())
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

        var client = SSHKeyExchangeStateMachine(allocator: allocator, role: .client, remoteVersion: Constants.version)
        var server = SSHKeyExchangeStateMachine(allocator: allocator, role: .server(.init(ed25519Key: .init())), remoteVersion: Constants.version)

        // Both sides begin by generating a key exchange message.
        let serverMessage = try assertGeneratesKeyExchangeMessage(server.startKeyExchange())
        let clientMessage = try assertGeneratesKeyExchangeMessage(client.startKeyExchange())
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        // The server does not generate a response message, but the client does.
        try assertGeneratesNoMessage(server.handle(keyExchange: clientMessage))

        let ecdhInit = try assertGeneratesECDHKeyExchangeInit(client.handle(keyExchange: serverMessage))
        client.send(keyExchangeInit: ecdhInit)

        // Now the server receives the ECDH init message and generates the reply, as well as the newKeys message.
        let ecdhReply = try assertGeneratesECDHKeyExchangeReply(server.handle(keyExchangeInit: ecdhInit))
        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        let serverOutboundProtection = server.sendNewKeys()

        // Now the client receives the reply and newKeys, and generates a newKeys message.
        try assertGeneratesNewKeys(client.handle(keyExchangeReply: ecdhReply))
        let clientInboundProtection = try assertNoThrowWithValue(client.handleNewKeys())
        let clientOutboundProtection = client.sendNewKeys()

        // Server receives the newKeys.
        let serverInboundProtection = try assertNoThrowWithValue(server.handleNewKeys())

        // Each peer has generated the exact same protection object for both directions.
        XCTAssertTrue(clientInboundProtection === clientOutboundProtection)
        XCTAssertTrue(serverInboundProtection === serverOutboundProtection)

        assertCompatibleProtection(client: clientInboundProtection, server: serverInboundProtection)
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
