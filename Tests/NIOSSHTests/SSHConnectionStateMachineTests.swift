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

import XCTest
import NIO
import Crypto
@testable import NIOSSH


final class ExplodingAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    enum Error: Swift.Error {
        case kaboom
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        XCTFail("Next Authentication Type must not be called")
        nextChallengePromise.fail(Error.kaboom)
    }
}


final class SSHConnectionStateMachineTests: XCTestCase {
    private func assertSuccessfulConnection(client: inout SSHConnectionStateMachine, server: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop, clientAuthDelegate: UserAuthDelegate, serverAuthDelegate: UserAuthDelegate) throws {
        var clientMessage: SSHMultiMessage? = client.start()
        var serverMessage: SSHMultiMessage? = server.start()
        var clientBuffer = allocator.buffer(capacity: 1024)
        var serverBuffer = allocator.buffer(capacity: 1024)
        var waitingForClientMessage = false
        var waitingForServerMessage = false

        while clientMessage != nil || serverMessage != nil {
            if let clientMessage = clientMessage {
                for message in clientMessage {
                    XCTAssertNoThrow(try client.processOutboundMessage(message, buffer: &clientBuffer, allocator: allocator, loop: loop, userAuthDelegate: clientAuthDelegate))
                }
            }

            if let serverMessage = serverMessage {
                for message in serverMessage {
                    XCTAssertNoThrow(try server.processOutboundMessage(message, buffer: &serverBuffer, allocator: allocator, loop: loop, userAuthDelegate: serverAuthDelegate))
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

            switch try assertNoThrowWithValue(client.processInboundMessage(allocator: allocator, loop: loop, userAuthDelegate: clientAuthDelegate)) {
            case .some(.emitMessage(let message)):
                clientMessage = message
            case .some(.noMessage), .none:
                clientMessage = nil
            case .some(.possibleFutureMessage(let futureMessage)):
                waitingForClientMessage = true
                clientMessage = nil

                futureMessage.whenComplete { result in
                    waitingForClientMessage = false

                    switch result {
                    case .failure(let err):
                        XCTFail("Unexpected error in delayed message production: \(err)")
                    case .success(let message):
                        if clientMessage != nil {
                            XCTFail("Produced extra client message!")
                        } else {
                            clientMessage = message
                        }
                    }
                }
            case .some(.forwardToMultiplexer), .some(.disconnect):
                fatalError("Currently unsupported")
            }

            switch try assertNoThrowWithValue(server.processInboundMessage(allocator: allocator, loop: loop, userAuthDelegate: serverAuthDelegate)) {
            case .some(.emitMessage(let message)):
                serverMessage = message
            case .some(.noMessage), .none:
                serverMessage = nil
            case .some(.possibleFutureMessage(let futureMessage)):
                waitingForServerMessage = true
                serverMessage = nil
                
                futureMessage.whenComplete { result in
                    waitingForServerMessage = false

                    switch result {
                    case .failure(let err):
                        XCTFail("Unexpected error in delayed message production: \(err)")
                    case .success(let message):
                        if serverMessage != nil {
                            XCTFail("Produced extra server message!")
                        } else {
                            serverMessage = message
                        }
                    }
                }
            case .some(.forwardToMultiplexer), .some(.disconnect):
                fatalError("Currently unsupported")
            }

            // Bottom of the loop, run the event loop to fire any futures we might need.
            loop.run()
        }

        XCTAssertFalse(waitingForClientMessage, "Loop exited while waiting for a client message")
        XCTAssertFalse(waitingForServerMessage, "Loop exited while waiting for a server message")
    }

    private func assertForwardsToMultiplexer(_ message: SSHMessage, sender: inout SSHConnectionStateMachine, receiver: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop, userAuthDelegate: .client(ExplodingAuthDelegate())))
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop, userAuthDelegate: .client(ExplodingAuthDelegate())))

        switch result {
        case .some(.forwardToMultiplexer(let forwardedMessage)):
            XCTAssertEqual(forwardedMessage, message)
        case .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage), .some(.disconnect), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    private func assertSendingIsProtocolError(_ message: SSHMessage, sender: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertThrowsError(try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop, userAuthDelegate: .client(ExplodingAuthDelegate()))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
        XCTAssertEqual(tempBuffer.readableBytes, 0)
    }

    private func assertDisconnects(_ message: SSHMessage, sender: inout SSHConnectionStateMachine, receiver: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator, loop: EmbeddedEventLoop) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop, userAuthDelegate: .client(ExplodingAuthDelegate())))
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop, userAuthDelegate: .client(ExplodingAuthDelegate())))

        switch result {
        case .some(.disconnect):
            // Good
            break
        case .some(.forwardToMultiplexer), .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    func testBasicConnectionDance() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client)
        var server = SSHConnectionStateMachine(role: .server([NIOSSHPrivateKey(ed25519Key: .init())]))
        let clientAuthDelegate = InfinitePasswordDelegate()
        let serverAuthDelegate = DenyThenAcceptDelegate(messagesToDeny: 1)

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop, clientAuthDelegate: .client(clientAuthDelegate), serverAuthDelegate: .server(serverAuthDelegate))

        XCTAssertTrue(client.canInitializeChildChannels)
        XCTAssertTrue(server.canInitializeChildChannels)
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
        var client = SSHConnectionStateMachine(role: .client)
        var server = SSHConnectionStateMachine(role: .server([NIOSSHPrivateKey(ed25519Key: .init())]))
        let clientAuthDelegate = InfinitePasswordDelegate()
        let serverAuthDelegate = DenyThenAcceptDelegate(messagesToDeny: 1)

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop, clientAuthDelegate: .client(clientAuthDelegate), serverAuthDelegate: .server(serverAuthDelegate))

        for message in channelMessages {
            XCTAssertNoThrow(try assertForwardsToMultiplexer(message, sender: &client, receiver: &server, allocator: allocator, loop: loop))
        }
    }

    func testDisconnectMessageCausesImmediateConnectionClose() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client)
        var server = SSHConnectionStateMachine(role: .server([NIOSSHPrivateKey(ed25519Key: .init())]))
        let clientAuthDelegate = InfinitePasswordDelegate()
        let serverAuthDelegate = DenyThenAcceptDelegate(messagesToDeny: 0)

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop, clientAuthDelegate: .client(clientAuthDelegate), serverAuthDelegate: .server(serverAuthDelegate))

        XCTAssertFalse(client.disconnected)
        XCTAssertFalse(server.disconnected)

        // Have the client send and the server receive a disconnection message.
        try assertDisconnects(.disconnect(.init(reason: 0, description: "", tag: "")), sender: &client, receiver: &server, allocator: allocator, loop: loop)

        XCTAssertTrue(client.disconnected)
        XCTAssertTrue(server.disconnected)

        // Further messages are not sent.
        for message in channelMessages {
            XCTAssertNoThrow(try assertSendingIsProtocolError(message, sender: &client, allocator: allocator, loop: loop))
        }
    }
}
