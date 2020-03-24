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
            }

            // Bottom of the loop, run the event loop to fire any futures we might need.
            loop.run()
        }

        XCTAssertFalse(waitingForClientMessage, "Loop exited while waiting for a client message")
        XCTAssertFalse(waitingForServerMessage, "Loop exited while waiting for a server message")
    }

    func testBasicConnectionDance() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(role: .client)
        var server = SSHConnectionStateMachine(role: .server(NIOSSHHostPrivateKey(ed25519Key: .init())))
        let clientAuthDelegate = InfinitePasswordDelegate()
        let serverAuthDelegate = DenyThenAcceptDelegate(messagesToDeny: 1)

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop, clientAuthDelegate: .client(clientAuthDelegate), serverAuthDelegate: .server(serverAuthDelegate))

        // We want to be able to test more stuff here, but right now we can't do anything with the state machine once it exists.
    }
}
