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
    enum State {
        /// The connection has not begun.
        case idle(IdleState)

        /// We have sent our version message.
        case sentVersion(SentVersionState)

        /// We are in the process of actively performing a key exchange operation. Neither side has sent its newKeys message yet.
        case keyExchange(KeyExchangeState)

        /// We are performing a key exchange. We have sent our newKeys message, but not yet received one from our peer.
        case sentNewKeys(SentNewKeysState)

        /// We are performing a key exchange. We have received the peer newKeys message, but not yet sent one ourselves.
        case receivedNewKeys(ReceivedNewKeysState)

        case channel
    }

    /// The state of this state machine.
    private var state: State

    init(role: SSHConnectionRole, allocator: ByteBufferAllocator) {
        self.state = .idle(IdleState(role: role))
    }

    func start() -> SSHMessage {
        switch self.state {
        case .idle:
            return SSHMessage.version(Constants.version)
        case .sentVersion, .keyExchange, .sentNewKeys, .receivedNewKeys, .channel:
            preconditionFailure("Cannot call start twice, state \(self.state)")
        }
    }

    mutating func bufferInboundData(_ data: inout ByteBuffer) {
        switch self.state {
        case .idle:
            preconditionFailure("Cannot receive inbound data in idle state")
        case .sentVersion(var state):
            state.parser.append(bytes: &data)
            self.state = .sentVersion(state)
        case .keyExchange(var state):
            state.parser.append(bytes: &data)
            self.state = .keyExchange(state)
        case .receivedNewKeys(var state):
            state.parser.append(bytes: &data)
            self.state = .receivedNewKeys(state)
        case .sentNewKeys(var state):
            state.parser.append(bytes: &data)
            self.state = .sentNewKeys(state)
        case .channel:
            break
        }
    }

    mutating func processInboundMessage(allocator: ByteBufferAllocator) throws -> StateMachineInboundProcessResult? {
        switch self.state {
        case .idle:
            preconditionFailure("Received messages before sending our first message.")
        case .sentVersion(var state):
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .version(let version):
                try state.receiveVersionMessage(version)
                var newState = KeyExchangeState(sentVersionState: state, allocator: allocator, remoteVersion: version)
                let message = newState.keyExchangeStateMachine.startKeyExchange()
                self.state = .keyExchange(newState)
                return .emitMessage(message)
            default:
                throw NIOSSHError.protocolViolation(protocolName: "transport", violation: "Did not receive version message")
            }
        case .keyExchange(var state):
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .keyExchange(let message):
                let result = try state.receiveKeyExchangeMessage(message)
                self.state = .keyExchange(state)
                return result
            case .keyExchangeInit(let message):
                let result = try state.receiveKeyExchangeInitMessage(message)
                self.state = .keyExchange(state)
                return result
            case .keyExchangeReply(let message):
                let result = try state.receiveKeyExchangeReplyMessage(message)
                self.state = .keyExchange(state)
                return result
            case .newKeys:
                let result = try state.receiveNewKeysMessage()
                self.state = .receivedNewKeys(.init(keyExchangeState: state))
                return result
            default:
                // TODO: enforce RFC 4253:
                //
                // > Once a party has sent a SSH_MSG_KEXINIT message for key exchange or
                // > re-exchange, until it has sent a SSH_MSG_NEWKEYS message (Section
                // > 7.3), it MUST NOT send any messages other than:
                // >
                // > o  Transport layer generic messages (1 to 19) (but
                // >    SSH_MSG_SERVICE_REQUEST and SSH_MSG_SERVICE_ACCEPT MUST NOT be
                // >    sent);
                // >
                // > o  Algorithm negotiation messages (20 to 29) (but further
                // >    SSH_MSG_KEXINIT messages MUST NOT be sent);
                // >
                // > o  Specific key exchange method messages (30 to 49).
                //
                // We should enforce that, but right now we don't have a good mechanism by which to do so.
                return .noMessage
            }
        case .sentNewKeys(var state):
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .keyExchange(let message):
                let result = try state.receiveKeyExchangeMessage(message)
                self.state = .sentNewKeys(state)
                return result
            case .keyExchangeInit(let message):
                let result = try state.receiveKeyExchangeInitMessage(message)
                self.state = .sentNewKeys(state)
                return result
            case .keyExchangeReply(let message):
                let result = try state.receiveKeyExchangeReplyMessage(message)
                self.state = .sentNewKeys(state)
                return result
            case .newKeys:
                let result = try state.receiveNewKeysMessage()
                self.state = .channel
                return result
            default:
                // TODO: enforce RFC 4253:
                //
                // > Once a party has sent a SSH_MSG_KEXINIT message for key exchange or
                // > re-exchange, until it has sent a SSH_MSG_NEWKEYS message (Section
                // > 7.3), it MUST NOT send any messages other than:
                // >
                // > o  Transport layer generic messages (1 to 19) (but
                // >    SSH_MSG_SERVICE_REQUEST and SSH_MSG_SERVICE_ACCEPT MUST NOT be
                // >    sent);
                // >
                // > o  Algorithm negotiation messages (20 to 29) (but further
                // >    SSH_MSG_KEXINIT messages MUST NOT be sent);
                // >
                // > o  Specific key exchange method messages (30 to 49).
                //
                // We should enforce that, but right now we don't have a good mechanism by which to do so.
                return .noMessage
            }
        case .receivedNewKeys, .channel:
            // TODO: we now have keys
            return .noMessage
        }
    }

    mutating func processOutboundMessage(_ message: SSHMessage, buffer: inout ByteBuffer, allocator: ByteBufferAllocator) throws {
        switch self.state {
        case .idle(var state):
            switch message {
            case .version:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentVersion(.init(idleState: state, allocator: allocator))
            default:
                preconditionFailure("First message sent must be version, not \(message)")
            }

        case .sentVersion:
            // We can't send anything else now.
            // TODO(cory): We could refactor the key exchange state machine to accept the delayed version from the
            // remote peer, and then we unlock the ability to remove another RTT to the remote peer.
            preconditionFailure("Cannot send other messages before receiving version.")

        case .keyExchange(var kex):
            switch message {
            case .keyExchange(let keyExchangeMessage):
                try kex.sendKeyExchangeMessage(keyExchangeMessage, into: &buffer)
                self.state = .keyExchange(kex)
            case .keyExchangeInit(let kexInit):
                try kex.sendKeyExchangeInitMessage(kexInit, into: &buffer)
                self.state = .keyExchange(kex)
            case .keyExchangeReply(let kexReply):
                try kex.sendKeyExchangeReplyMessage(kexReply, into: &buffer)
                self.state = .keyExchange(kex)
            case .newKeys:
                try kex.sendNewKeysMessage(into: &buffer)
                self.state = .sentNewKeys(.init(keyExchangeState: kex))

            default:
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Sent unexpected message type: \(message)")
            }

        case .receivedNewKeys(var kex):
            switch message {
            case .keyExchange(let keyExchangeMessage):
                try kex.sendKeyExchangeMessage(keyExchangeMessage, into: &buffer)
                self.state = .receivedNewKeys(kex)
            case .keyExchangeInit(let kexInit):
                try kex.sendKeyExchangeInitMessage(kexInit, into: &buffer)
                self.state = .receivedNewKeys(kex)
            case .keyExchangeReply(let kexReply):
                try kex.sendKeyExchangeReplyMessage(kexReply, into: &buffer)
                self.state = .receivedNewKeys(kex)
            case .newKeys:
                try kex.sendNewKeysMessage(into: &buffer)
                self.state = .channel

            default:
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Sent unexpected message type: \(message)")
            }

        case .sentNewKeys, .channel:
            // We can't send anything in these states.
            break
        }
    }
}


extension SSHConnectionStateMachine {
    /// The result of spinning the state machine with an inbound message.
    ///
    /// When the state machine processes a message, several things may happen. Firstly, it may generate an
    /// automatic message that should be sent. Secondly, it may generate a possibility of having a message in
    /// future. Thirdly, it may generate nothing.
    enum StateMachineInboundProcessResult {
        case emitMessage(SSHMessage)
        case possibleFutureMessage(EventLoopFuture<SSHMessage?>)
        case noMessage
    }
}
