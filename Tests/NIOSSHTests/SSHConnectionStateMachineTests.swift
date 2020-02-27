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
    private func assertSuccessfulConnection(client: inout SSHConnectionStateMachine, server: inout SSHConnectionStateMachine, allocator: ByteBufferAllocator) throws {
        var clientMessage: SSHMessage? = client.start()
        var serverMessage: SSHMessage? = server.start()
        var clientBuffer = allocator.buffer(capacity: 1024)
        var serverBuffer = allocator.buffer(capacity: 1024)

        while clientMessage != nil || serverMessage != nil {
            if let clientMessage = clientMessage {
                XCTAssertNoThrow(try client.processOutboundMessage(clientMessage, buffer: &clientBuffer, allocator: allocator))
            }

            if let serverMessage = serverMessage {
                XCTAssertNoThrow(try server.processOutboundMessage(serverMessage, buffer: &serverBuffer, allocator: allocator))
            }

            if clientBuffer.readableBytes > 0 {
                server.bufferInboundData(&clientBuffer)
                clientBuffer.clear()
            }

            if serverBuffer.readableBytes > 0 {
                client.bufferInboundData(&serverBuffer)
                serverBuffer.clear()
            }

            switch try assertNoThrowWithValue(client.processInboundMessage(allocator: allocator)) {
            case .some(.emitMessage(let message)):
                clientMessage = message
            case .some(.noMessage), .none:
                clientMessage = nil
            case .some(.possibleFutureMessage):
                preconditionFailure("No current support for asynchronous message production.")
            }

            switch try assertNoThrowWithValue(server.processInboundMessage(allocator: allocator)) {
            case .some(.emitMessage(let message)):
                serverMessage = message
            case .some(.noMessage), .none:
                serverMessage = nil
            case .some(.possibleFutureMessage):
                preconditionFailure("No current support for asynchronous message production.")
            }
        }
    }

    func testBasicConnectionDance() throws {
        let allocator = ByteBufferAllocator()
        var client = SSHConnectionStateMachine(role: .client, allocator: allocator)
        var server = SSHConnectionStateMachine(role: .server(NIOSSHHostPrivateKey(ed25519Key: .init())), allocator: allocator)

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator)

        // We want to be able to test more stuff here, but right now we can't do anything with the state machine once it exists.
    }
}
