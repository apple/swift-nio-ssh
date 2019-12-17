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

import NIO

struct SSHConnectionStateMachine {
    enum SSHConnectionError: Error {
        case unsupportedVersion
    }

    enum State {
        case idle
        case banner
        case keyExchange(SSHKeyExchangeStateMachine)
        case channel(NIOSSHSessionKeys)
    }

    let role: SSHConnectionRole
    var state: State = .idle

    init(role: SSHConnectionRole) {
        self.role = role
    }

    mutating func start() -> SSHMessage {
        let message = SSHMessage.version(Constants.version)
        self.state = .banner
        return message
    }

    private func validateVersion(_ version: String) throws {
        guard version.count > 7, version.hasPrefix("SSH-") else {
            throw SSHConnectionError.unsupportedVersion
        }
        let start = version.index(version.startIndex, offsetBy: 4)
        let end = version.index(start, offsetBy: 3)
        guard version[start..<end] == "2.0" else {
            throw SSHConnectionError.unsupportedVersion
        }
    }

    mutating func process(context: ChannelHandlerContext, message: SSHMessage) throws -> SSHMessage? {
        switch self.state {
        case .idle:
            // TODO: should be error
            break
        case .banner:
            switch message {
            case .version(let version):
                var exchange = SSHKeyExchangeStateMachine(allocator: context.channel.allocator, role: self.role, remoteVersion: version)

                switch self.role {
                case .client:
                    let message = try exchange.startKeyExchange()
                    self.state = .keyExchange(exchange)
                    return message
                case .server:
                    self.state = .keyExchange(exchange)
                    return nil
                }
            default:
                // TODO: exhaustive switch?
                break
            }
        case .keyExchange(var exchange):
            switch message {
            case .keyExchange(let message):
                let message = try exchange.handle(keyExchange: message)
                self.state = .keyExchange(exchange)
                return message
            case .keyExchangeInit(let message):
                let message = try exchange.handle(keyExchangeInit: message)
                self.state = .keyExchange(exchange)
                return message
            case .keyExchangeReply(let message):
                let message = try exchange.handle(keyExchangeReply: message)
                self.state = .keyExchange(exchange)
                return message
            case .newKeys:
                let result = try exchange.newKeys()
                self.state = .channel(result.keys)
            default:
                // TODO: exhaustive switch?
                break
            }
        case .channel(let keys):
            // TODO: we now have keys
            break
        }
        return nil
    }
}
