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

        var client = SSHKeyExchangeStateMachine(allocator: allocator, role: .client)
        var server = SSHKeyExchangeStateMachine(allocator: allocator, role: .server(.init(ed25519Key: .init())))

        XCTAssertThrowsError(try client.handle(version: "SSH-2.0-SwiftNIOSSH_1.0"))
        XCTAssertThrowsError(try server.handle(version: "SSH-2.0-SwiftNIOSSH_1.0"))

        var message = try server.start()
        XCTAssertNil(try client.start())

        XCTAssertThrowsError(try client.start())
        XCTAssertThrowsError(try server.start())

        let version: String
        switch message {
        case .version(let v):
            version = v
        default:
            throw SSHKeyExchangeStateMachine.SSHKeyExchangeError.unexpectedMessage
        }

        XCTAssertNil(try server.handle(version: "SSH-2.0-SwiftNIOSSH_1.0"))
        message = try client.handle(version: version)

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

        _ = try server.newKeys()
        _ = try client.newKeys()
    }

    func testVersionValidation() throws {
        let allocator = ByteBufferAllocator()

        var client = SSHKeyExchangeStateMachine(allocator: allocator, role: .client)
        var server = SSHKeyExchangeStateMachine(allocator: allocator, role: .server(.init(ed25519Key: .init())))

        _ = try client.start()
        _ = try server.start()

        XCTAssertThrowsError(try client.handle(version: "BAD"))
        XCTAssertThrowsError(try server.handle(version: "BAD"))

        XCTAssertThrowsError(try client.handle(version: "SSH-1.9-SwiftNIOSSH_1.0"))
        XCTAssertThrowsError(try server.handle(version: "SSH-1.9-SwiftNIOSSH_1.0"))
    }
}
