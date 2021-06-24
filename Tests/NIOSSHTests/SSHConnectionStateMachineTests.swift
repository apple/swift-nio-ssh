//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIO
@testable import NIOSSH
import XCTest

final class ExplodingAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    enum Error: Swift.Error {
        case kaboom
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        XCTFail("Next Authentication Type must not be called")
        nextChallengePromise.fail(Error.kaboom)
    }
}

final class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        validationCompletePromise.succeed(())
    }
}

final class SSHConnectionStateMachineTests: XCTestCase {
    private func assertSuccessfulConnection(client: inout SSHConnectionStateMachine, server: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var clientMessage: SSHMultiMessage? = client.start()
        var serverMessage: SSHMultiMessage? = server.start()
        var clientBuffer = allocator.buffer(capacity: 1024)
        var serverBuffer = allocator.buffer(capacity: 1024)
        var waitingForClientMessage = false
        var waitingForServerMessage = false

        while clientMessage != nil || serverMessage != nil {
            if let clientMessage = clientMessage {
                for message in clientMessage {
                    XCTAssertNoThrow(try client.processOutboundMessage(message, buffer: &clientBuffer, allocator: allocator, loop: loop))
                }
            }

            if let serverMessage = serverMessage {
                for message in serverMessage {
                    XCTAssertNoThrow(try server.processOutboundMessage(message, buffer: &serverBuffer, allocator: allocator, loop: loop))
                }
            }

            if clientBuffer.readableBytes > 0 {
                server.bufferInboundData(&clientBuffer)
                clientBuffer.clear()
            }

            if serverBuffer.readableBytes > 0 {
                client.bufferInboundData(&serverBuffer)
                serverBuffer.clear()
            }

            clientMessage = nil
            serverMessage = nil

            clientLoop: while true {
                switch try assertNoThrowWithValue(client.processInboundMessage(allocator: allocator, loop: loop)) {
                case .some(.emitMessage(let message)):
                    clientMessage.append(message)
                case .none:
                    break clientLoop
                case .some(.noMessage):
                    ()
                case .some(.possibleFutureMessage(let futureMessage)):
                    waitingForClientMessage = true

                    futureMessage.whenComplete { result in
                        waitingForClientMessage = false

                        switch result {
                        case .failure(let err):
                            XCTFail("Unexpected error in delayed message production: \(err)")
                        case .success(let message):
                            if let message = message {
                                clientMessage.append(message)
                            }
                        }
                    }
                case .some(.forwardToMultiplexer), .some(.globalRequest), .some(.globalRequestResponse), .some(.disconnect):
                    fatalError("Currently unsupported")
                case .some(.event):
                    ()
                }
            }

            serverLoop: while true {
                switch try assertNoThrowWithValue(server.processInboundMessage(allocator: allocator, loop: loop)) {
                case .some(.emitMessage(let message)):
                    serverMessage.append(message)
                case .none:
                    break serverLoop
                case .some(.noMessage):
                    ()
                case .some(.possibleFutureMessage(let futureMessage)):
                    waitingForServerMessage = true

                    futureMessage.whenComplete { result in
                        waitingForServerMessage = false

                        switch result {
                        case .failure(let err):
                            XCTFail("Unexpected error in delayed message production: \(err)")
                        case .success(let message):
                            if let message = message {
                                serverMessage.append(message)
                            }
                        }
                    }
                case .some(.forwardToMultiplexer), .some(.globalRequest), .some(.globalRequestResponse), .some(.disconnect), .some(.event):
                    fatalError("Currently unsupported")
                }
            }

            // Bottom of the loop, run the event loop to fire any futures we might need.
            loop.run()
        }

        XCTAssertFalse(waitingForClientMessage, "Loop exited while waiting for a client message")
        XCTAssertFalse(waitingForServerMessage, "Loop exited while waiting for a server message")
    }

    private func assertForwardsToMultiplexer(_ message: SSHMessage, sender: inout SSHConnectionStateMachine, receiver: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop))
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.forwardToMultiplexer(let forwardedMessage)):
            XCTAssertEqual(forwardedMessage, message)
        case .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage), .some(.globalRequest), .some(.globalRequestResponse), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    private func assertSendingIsProtocolError(_ message: SSHMessage, sender: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertThrowsError(try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
        XCTAssertEqual(tempBuffer.readableBytes, 0)
    }

    private func assertDisconnects(_ message: SSHMessage, sender: inout SSHConnectionStateMachine, receiver: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop))
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.disconnect):
            // Good
            break
        case .some(.forwardToMultiplexer), .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage), .some(.globalRequest), .some(.globalRequestResponse), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    private func assertTriggersGlobalRequest(_ message: SSHMessage, sender: inout SSHConnectionStateMachine, receiver: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop))
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.globalRequest(let receivedMessage)):
            // Good
            XCTAssertEqual(.globalRequest(receivedMessage), message)
        case .some(.forwardToMultiplexer), .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage), .some(.globalRequestResponse), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    private func assertTriggersGlobalRequestResponse(_ message: SSHMessage, sender: inout SSHConnectionStateMachine, receiver: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult.GlobalRequestResponse? {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop))
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.globalRequestResponse(let response)):
            // Good
            return response
        case .some(.forwardToMultiplexer), .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage), .some(.globalRequest), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
            return nil
        }
    }

    func assertTriggersNothing(_ message: SSHMessage, sender: inout SSHConnectionStateMachine, receiver: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop))
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.noMessage):
            // Good
            break
        case .some(.forwardToMultiplexer), .some(.emitMessage), .some(.possibleFutureMessage), .some(.globalRequest), .some(.globalRequestResponse), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    private func assertUnimplementedCausesError(sequenceNumber: UInt32, sender: inout SSHConnectionStateMachine, receiver: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try sender.processOutboundMessage(.unimplemented(.init(sequenceNumber: sequenceNumber)), buffer: &tempBuffer, allocator: allocator, loop: loop))
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        XCTAssertThrowsError(try receiver.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .remotePeerDoesNotSupportMessage)
        }
    }

    func testBasicConnectionDance() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        XCTAssertTrue(client.isActive)
        XCTAssertTrue(server.isActive)
    }

    // Messages that are usable once child channels are allowed.
    let channelMessages: [SSHMessage] = [
        .channelOpen(.init(type: .session, senderChannel: 0, initialWindowSize: 0, maximumPacketSize: 12)),
        .channelOpenConfirmation(.init(recipientChannel: 0, senderChannel: 0, initialWindowSize: 0, maximumPacketSize: 12)),
        .channelOpenFailure(.init(recipientChannel: 0, reasonCode: 0, description: "foo", language: "bar")),
        .channelEOF(.init(recipientChannel: 0)),
        .channelClose(.init(recipientChannel: 0)),
        .channelWindowAdjust(.init(recipientChannel: 0, bytesToAdd: 1)),
        .channelData(.init(recipientChannel: 0, data: ByteBufferAllocator().buffer(capacity: 0))),
        .channelExtendedData(.init(recipientChannel: 0, dataTypeCode: .stderr, data: ByteBufferAllocator().buffer(capacity: 0))),
        .channelRequest(.init(recipientChannel: 0, type: .exec("uname"), wantReply: false)),
        .channelSuccess(.init(recipientChannel: 0)),
        .channelFailure(.init(recipientChannel: 0)),
    ]

    func testReceivingChannelMessagesGetForwardedOnceConnectionMade() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))
        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        for message in self.channelMessages {
            XCTAssertNoThrow(try self.assertForwardsToMultiplexer(message, sender: &client, receiver: &server, allocator: allocator, loop: loop))
        }
    }

    func testDisconnectMessageCausesImmediateConnectionClose() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        XCTAssertFalse(client.disconnected)
        XCTAssertFalse(server.disconnected)

        // Have the client send and the server receive a disconnection message.
        try self.assertDisconnects(.disconnect(.init(reason: 0, description: "", tag: "")), sender: &client, receiver: &server, allocator: allocator, loop: loop)

        XCTAssertTrue(client.disconnected)
        XCTAssertTrue(server.disconnected)

        // Further messages are not sent.
        for message in self.channelMessages {
            XCTAssertNoThrow(try self.assertSendingIsProtocolError(message, sender: &client, allocator: allocator, loop: loop))
        }
    }

    func testDisconnectedReturnsNil() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)
        try self.assertDisconnects(.disconnect(.init(reason: 0, description: "", tag: "")), sender: &client, receiver: &server, allocator: allocator, loop: loop)

        // Ok, in disconnected state. At this time, any attempt to process the connection should return nil.
        var junkBuffer = allocator.buffer(capacity: 1024)
        junkBuffer.writeBytes(0 ... 255)
        server.bufferInboundData(&junkBuffer)

        XCTAssertNoThrow(try XCTAssertNil(server.processInboundMessage(allocator: allocator, loop: loop)))
    }

    func testGlobalRequestCanBeSent() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        var message = SSHMessage.GlobalRequestMessage(wantReply: true, type: .tcpipForward("foo", 66))
        try self.assertTriggersGlobalRequest(.globalRequest(message), sender: &client, receiver: &server, allocator: allocator, loop: loop)

        message = SSHMessage.GlobalRequestMessage(wantReply: false, type: .cancelTcpipForward("foo", 66))
        try self.assertTriggersGlobalRequest(.globalRequest(message), sender: &client, receiver: &server, allocator: allocator, loop: loop)
    }

    func testGlobalRequestResponsesTriggerResponse() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        // Deliver a request success message.
        var response = try self.assertTriggersGlobalRequestResponse(
            .requestSuccess(.init(.tcpForwarding(.init(boundPort: 6)), allocator: allocator)), sender: &server, receiver: &client, allocator: allocator, loop: loop
        )
        guard case .some(.success(let firstResponse)) = response, GlobalRequest.TCPForwardingResponse(firstResponse).boundPort == 6 else {
            XCTFail("Unexpected response: \(String(describing: response))")
            return
        }

        // Now without a port.
        response = try self.assertTriggersGlobalRequestResponse(
            .requestSuccess(.init(.tcpForwarding(.init(boundPort: nil)), allocator: allocator)), sender: &server, receiver: &client, allocator: allocator, loop: loop
        )
        guard case .some(.success(let secondResponse)) = response, GlobalRequest.TCPForwardingResponse(secondResponse).boundPort == nil else {
            XCTFail("Unexpected response: \(String(describing: response))")
            return
        }

        // Now a failure.
        response = try self.assertTriggersGlobalRequestResponse(
            .requestFailure, sender: &server, receiver: &client, allocator: allocator, loop: loop
        )
        guard case .some(.failure) = response else {
            XCTFail("Unexpected response: \(String(describing: response))")
            return
        }
    }

    func testIgnoreDebugAndIgnoreMessages() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        try self.assertTriggersNothing(.ignore(.init(data: allocator.buffer(capacity: 1024))), sender: &client, receiver: &server, allocator: allocator, loop: loop)
        try self.assertTriggersNothing(.debug(.init(alwaysDisplay: true, message: "foo", language: "bar")), sender: &client, receiver: &server, allocator: allocator, loop: loop)
    }

    func testUnimplementedGivesARichError() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)
        try self.assertUnimplementedCausesError(sequenceNumber: 0, sender: &client, receiver: &server, allocator: allocator, loop: loop)
    }

    func testWeTolerateMessagesAfterSendingKexInit() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        // Ok, the server is going to try to rekey.
        var buffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try server.beginRekeying(buffer: &buffer, allocator: allocator, loop: loop))

        // We're not passing this to the client though. Now we'll send all the channel messages through: the server should tolerate them
        // all.
        for message in self.channelMessages {
            XCTAssertNoThrow(try self.assertForwardsToMultiplexer(message, sender: &client, receiver: &server, allocator: allocator, loop: loop))
        }
    }

    func testWeTolerateMultipleStarts() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))

        let message = client.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(try client.processOutboundMessage(SSHMessage.version(Constants.version), buffer: &buffer, allocator: allocator, loop: loop))

        XCTAssertNil(client.start())
    }

    func testClientToleratesLinesBeforeVersion() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))

        let message = client.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(try client.processOutboundMessage(SSHMessage.version(Constants.version), buffer: &buffer, allocator: allocator, loop: loop))

        var version = ByteBuffer(string: "xxxx\nyyy\nSSH-2.0-OpenSSH_8.1\r\n")
        client.bufferInboundData(&version)

        XCTAssertNoThrow(try client.processInboundMessage(allocator: allocator, loop: loop))
    }

    func testServerRejectsLinesBeforeVersion() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var server = SSHConnectionStateMachine(role: .server(.init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))))

        let message = server.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(try server.processOutboundMessage(SSHMessage.version(Constants.version), buffer: &buffer, allocator: allocator, loop: loop))

        var version = ByteBuffer(string: "xxxx\nyyy\nSSH-2.0-OpenSSH_8.1\r\n")
        server.bufferInboundData(&version)

        XCTAssertThrowsError(try server.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testClintVersionNotFound() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))

        let message = client.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(try client.processOutboundMessage(SSHMessage.version(Constants.version), buffer: &buffer, allocator: allocator, loop: loop))

        var version = ByteBuffer(string: "SSH-\r\n")
        client.bufferInboundData(&version)

        XCTAssertThrowsError(try client.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testVersionNotSupported() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())))

        let message = client.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(try client.processOutboundMessage(SSHMessage.version(Constants.version), buffer: &buffer, allocator: allocator, loop: loop))

        var version = ByteBuffer(string: "SSH-1.0-OpenSSH_8.1\r\n")
        client.bufferInboundData(&version)

        XCTAssertThrowsError(try client.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unsupportedVersion)
        }
    }
}

extension Optional where Wrapped == SSHMultiMessage {
    mutating func append(_ message: SSHMultiMessage) {
        if let original = self {
            precondition(original.count == 1)
            precondition(message.count == 1)
            self = .some(SSHMultiMessage(original.first!, message.first!))
        } else {
            self = .some(message)
        }
    }
}
