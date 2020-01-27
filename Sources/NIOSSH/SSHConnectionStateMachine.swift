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

    private enum State {
        case idle
        case banner
        case keyExchange(SSHKeyExchangeStateMachine)
        case channel
    }

    /// The role that this state machine is operating in.
    internal let role: SSHConnectionRole

    /// The packet parser used by this state machine. This will automatically be
    /// updated with SSH encryption keys as needed.
    internal var parser: SSHPacketParser

    /// The packet serializer used by this state machine. This will automatically be
    /// updated with SSH encryption keys as needed.
    internal var serializer: SSHPacketSerializer

    /// The state of this state machine.
    private var state: State = .idle

    init(role: SSHConnectionRole, allocator: ByteBufferAllocator) {
        self.role = role
        self.parser = SSHPacketParser(allocator: allocator)
        self.serializer = SSHPacketSerializer()
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

    mutating func processInboundMessage(allocator: ByteBufferAllocator, message: SSHMessage) throws -> StateMachineProcessResult {
        switch self.state {
        case .idle:
            // TODO: should be error
            return .noMessage
        case .banner:
            switch message {
            case .version(let version):
                var exchange = SSHKeyExchangeStateMachine(allocator: allocator, role: self.role, remoteVersion: version)

                let message = exchange.startKeyExchange()
                self.state = .keyExchange(exchange)
                return .emitMessage(message)
            default:
                // TODO: exhaustive switch?
                return .noMessage
            }
        case .keyExchange(var exchange):
            switch message {
            case .keyExchange(let message):
                let message = try exchange.handle(keyExchange: message)
                self.state = .keyExchange(exchange)

                if let message = message {
                    return .emitMessage(message)
                } else {
                    return .noMessage
                }
            case .keyExchangeInit(let message):
                let message = try exchange.handle(keyExchangeInit: message)
                self.state = .keyExchange(exchange)

                if let message = message {
                    return .emitMessage(message)
                } else {
                    return .noMessage
                }
            case .keyExchangeReply(let message):
                let message = try exchange.handle(keyExchangeReply: message)
                self.state = .keyExchange(exchange)
                return .emitMessage(message)
            case .newKeys:
                // Received a new keys message. Apply the encryption keys to the parser.
                let result = try exchange.handleNewKeys()
                self.parser.addEncryption(result)
                self.state = .channel
                return .noMessage
            default:
                // TODO: exhaustive switch?
                return .noMessage
            }
        case .channel:
            // TODO: we now have keys
            return .noMessage
        }
    }
}


extension SSHConnectionStateMachine {
    /// The result of spinning the state machine.
    ///
    /// When the state machine processes a message, several things may happen. Firstly, it may generate an
    /// automatic message that should be sent. Secondly, it may generate a possibility of having a message in
    /// future. Thirdly, it may generate nothing.
    enum StateMachineProcessResult {
        case emitMessage(SSHMessage)
        case possibleFutureMessage(EventLoopFuture<SSHMessage?>)
        case noMessage
    }
}
