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
import CryptoKit
@testable import NIOSSH

final class SSHKeyExchangeStateMachineTests: XCTestCase {
    func testKeyExchange() throws {
        let allocator = ByteBufferAllocator()

        var client = SSHKeyExchangeStateMachine(allocator: allocator, role: .client, remoteVersion: SSHKeyExchangeStateMachine.version)
        var server = SSHKeyExchangeStateMachine(allocator: allocator, role: .server(.init(ed25519Key: .init())), remoteVersion: SSHKeyExchangeStateMachine.version)

        XCTAssertThrowsError(try server.startKeyExchange())
        var message = try client.startKeyExchange()

        var keyExchange: SSHMessage.KeyExchangeMessage
        switch message {
        case .keyExchange(let v):
            keyExchange = v
        default:
            throw SSHKeyExchangeStateMachine.SSHKeyExchangeError.unexpectedMessage
        }

        message = try server.handle(keyExchange: keyExchange)
        XCTAssertThrowsError(try server.handle(keyExchange: keyExchange))

        switch message {
        case .keyExchange(let v):
            keyExchange = v
        default:
            throw SSHKeyExchangeStateMachine.SSHKeyExchangeError.unexpectedMessage
        }

        message = try client.handle(keyExchange: keyExchange)
        XCTAssertThrowsError(try client.handle(keyExchange: keyExchange))

        let keyExchangeInit: SSHMessage.KeyExchangeECDHInitMessage
        switch message {
        case .keyExchangeInit(let v):
            keyExchangeInit = v
        default:
            throw SSHKeyExchangeStateMachine.SSHKeyExchangeError.unexpectedMessage
        }

        message = try server.handle(keyExchangeInit: keyExchangeInit)
        XCTAssertThrowsError(try server.handle(keyExchangeInit: keyExchangeInit))
        XCTAssertThrowsError(try client.handle(keyExchangeInit: keyExchangeInit))

        let keyExchangeReply: SSHMessage.KeyExchangeECDHReplyMessage
        switch message {
        case .keyExchangeReply(let v):
            keyExchangeReply = v
        default:
            throw SSHKeyExchangeStateMachine.SSHKeyExchangeError.unexpectedMessage
        }

        message = try client.handle(keyExchangeReply: keyExchangeReply)
        XCTAssertThrowsError(try client.handle(keyExchangeReply: keyExchangeReply))
        XCTAssertThrowsError(try server.handle(keyExchangeReply: keyExchangeReply))

        switch message {
        case .newKeys:
            break
        default:
            throw SSHKeyExchangeStateMachine.SSHKeyExchangeError.unexpectedMessage
        }

        let clients = try server.newKeys()
        let servers = try client.newKeys()

        XCTAssertEqual(clients.keys, servers.keys.inverted)
    }
}
