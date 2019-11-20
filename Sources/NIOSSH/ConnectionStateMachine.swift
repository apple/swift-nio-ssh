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

struct ConnectionStateMachine {
    enum State {
        case idle
        case banner
        case keyExchange(SSHKeyExchangeStateMachine)
        case channel(NIOSSHSessionKeys)
    }

    var state: State = .idle

    mutating func start() -> SSHMessage {
        let message = SSHMessage.version("SSH-2.0-SwiftNIOSSH_1.0")
        self.state = .banner
        return message
    }

    mutating func process(context: ChannelHandlerContext, message: SSHMessage) throws -> SSHMessage? {
        switch self.state {
        case .idle:
            // TODO: should be error
            break
        case .banner:
            switch message {
            case .version(let version):
                var exchange = SSHKeyExchangeStateMachine(allocator: context.channel.allocator)
                let message = try exchange.handle(version: version)

                self.state = .keyExchange(exchange)

                return message
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
