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

        /// We are currently performing a user authentication.
        case userAuthentication(UserAuthenticationState)

        /// The SSH connection is active.
        case active(ActiveState)

        /// We have received a KeyExchangeInit message from the active state, and so will be rekeying shortly.
        case receivedKexInitWhenActive(ReceivedKexInitWhenActiveState)

        /// We have sent a KeyExchangeInit message from the active state, and so will be rekeying shortly.
        case sentKexInitWhenActive(SentKexInitWhenActiveState)

        /// Both peers have sent KeyExchangeInit and are actively engaged in a key exchange to rekey.
        case rekeying(RekeyingState)

        /// We have sent our newKeys message, but have not yet received the peer newKeys for this rekeying operation.
        case rekeyingSentNewKeysState(RekeyingSentNewKeysState)

        /// We have received the peer newKeys message, but not yet sent our own for this rekeying operation.
        case rekeyingReceivedNewKeysState(RekeyingReceivedNewKeysState)

        case receivedDisconnect(SSHConnectionRole)

        case sentDisconnect(SSHConnectionRole)
    }

    /// The state of this state machine.
    private var state: State

    private static let defaultTransportProtectionSchemes: [NIOSSHTransportProtection.Type] = [
        AES256GCMOpenSSHTransportProtection.self, AES128GCMOpenSSHTransportProtection.self,
    ]

    init(role: SSHConnectionRole, protectionSchemes: [NIOSSHTransportProtection.Type] = Self.defaultTransportProtectionSchemes) {
        self.state = .idle(IdleState(role: role, protectionSchemes: protectionSchemes))
    }

    func start() -> SSHMultiMessage? {
        switch self.state {
        case .idle:
            return SSHMultiMessage(SSHMessage.version(Constants.version))
        case .sentVersion, .keyExchange, .sentNewKeys, .receivedNewKeys, .userAuthentication,
             .active, .receivedKexInitWhenActive, .sentKexInitWhenActive, .rekeying, .rekeyingReceivedNewKeysState,
             .rekeyingSentNewKeysState, .receivedDisconnect, .sentDisconnect:
            return nil
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
        case .userAuthentication(var state):
            state.parser.append(bytes: &data)
            self.state = .userAuthentication(state)
        case .active(var state):
            state.parser.append(bytes: &data)
            self.state = .active(state)
        case .receivedKexInitWhenActive(var state):
            state.parser.append(bytes: &data)
            self.state = .receivedKexInitWhenActive(state)
        case .sentKexInitWhenActive(var state):
            state.parser.append(bytes: &data)
            self.state = .sentKexInitWhenActive(state)
        case .rekeying(var state):
            state.parser.append(bytes: &data)
            self.state = .rekeying(state)
        case .rekeyingReceivedNewKeysState(var state):
            state.parser.append(bytes: &data)
            self.state = .rekeyingReceivedNewKeysState(state)
        case .rekeyingSentNewKeysState(var state):
            state.parser.append(bytes: &data)
            self.state = .rekeyingSentNewKeysState(state)
        case .receivedDisconnect, .sentDisconnect:
            // No more I/O, we're done.
            break
        }
    }

    mutating func processInboundMessage(allocator: ByteBufferAllocator,
                                        loop: EventLoop) throws -> StateMachineInboundProcessResult? {
        switch self.state {
        case .idle:
            preconditionFailure("Received messages before sending our first message.")
        case .sentVersion(var state):
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .version(let version):
                try state.receiveVersionMessage(version, role: self.role)
                let newState = KeyExchangeState(sentVersionState: state, allocator: allocator, loop: loop, remoteVersion: version)
                let message = newState.keyExchangeStateMachine.createKeyExchangeMessage()
                self.state = .keyExchange(newState)
                return .emitMessage(SSHMultiMessage(.keyExchange(message)))

            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect

            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)

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
                try state.receiveNewKeysMessage()
                self.state = .receivedNewKeys(.init(keyExchangeState: state, loop: loop))
                return .noMessage
            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect
            case .ignore, .debug:
                // Ignore these
                self.state = .keyExchange(state)
                return .noMessage
            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)
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
                throw NIOSSHError.protocolViolation(protocolName: "user auth", violation: "Unexpected user auth message: \(message)")
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
                try state.receiveNewKeysMessage()
                self.state = .userAuthentication(.init(sentNewKeysState: state))
                return .noMessage
            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect
            case .ignore, .debug:
                // Ignore these
                self.state = .sentNewKeys(state)
                return .noMessage
            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)

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
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Unexpected message: \(message)")
            }

        case .receivedNewKeys(var state):
            // In this state we tolerate receiving service request messages. As we haven't sent newKeys, we cannot
            // send any user auth messages yet, so by definition we can't receive any other user auth message.
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .serviceRequest(let message):
                let result = try state.receiveServiceRequest(message)
                self.state = .receivedNewKeys(state)
                return result

            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect

            case .ignore, .debug:
                // Ignore these
                self.state = .receivedNewKeys(state)
                return .noMessage

            case .serviceAccept, .userAuthRequest, .userAuthSuccess, .userAuthFailure:
                throw NIOSSHError.protocolViolation(protocolName: "user auth", violation: "Unexpected user auth message: \(message)")

            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "user auth", violation: "Unexpected inbound message: \(message)")
            }

        case .userAuthentication(var state):
            // In this state we tolerate receiving user auth messages.
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .serviceRequest(let message):
                let result = try state.receiveServiceRequest(message)
                self.state = .userAuthentication(state)
                return result

            case .serviceAccept(let message):
                let result = try state.receiveServiceAccept(message)
                self.state = .userAuthentication(state)
                return result

            case .userAuthRequest(let message):
                let result = try state.receiveUserAuthRequest(message)
                self.state = .userAuthentication(state)
                return result

            case .userAuthSuccess:
                let result = try state.receiveUserAuthSuccess()
                // Hey, auth succeeded!
                self.state = .active(ActiveState(state))
                return result

            case .userAuthFailure(let message):
                let result = try state.receiveUserAuthFailure(message)
                self.state = .userAuthentication(state)
                return result

            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect

            case .ignore, .debug:
                // Ignore these
                self.state = .userAuthentication(state)
                return .noMessage

            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "user auth", violation: "Unexpected inbound message: \(message)")
            }

        case .active(var state):
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .channelOpen(let message):
                try state.receiveChannelOpen(message)
            case .channelOpenConfirmation(let message):
                try state.receiveChannelOpenConfirmation(message)
            case .channelOpenFailure(let message):
                try state.receiveChannelOpenFailure(message)
            case .channelEOF(let message):
                try state.receiveChannelEOF(message)
            case .channelClose(let message):
                try state.receiveChannelClose(message)
            case .channelWindowAdjust(let message):
                try state.receiveChannelWindowAdjust(message)
            case .channelData(let message):
                try state.receiveChannelData(message)
            case .channelExtendedData(let message):
                try state.receiveChannelExtendedData(message)
            case .channelRequest(let message):
                try state.receiveChannelRequest(message)
            case .channelSuccess(let message):
                try state.receiveChannelSuccess(message)
            case .channelFailure(let message):
                try state.receiveChannelFailure(message)
            case .globalRequest(let message):
                try state.receiveGlobalRequest(message)
                self.state = .active(state)
                return .globalRequest(message)
            case .requestSuccess(let message):
                try state.receiveRequestSuccess(message)
                self.state = .active(state)
                return .globalRequestResponse(.success(message))
            case .requestFailure:
                try state.receiveRequestFailure()
                self.state = .active(state)
                return .globalRequestResponse(.failure)
            case .keyExchange(let message):
                // Attempting to rekey.
                var newState = ReceivedKexInitWhenActiveState(state, allocator: allocator, loop: loop)
                let result = try newState.receiveKeyExchangeMessage(message)
                self.state = .receivedKexInitWhenActive(newState)
                return result
            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect
            case .ignore, .debug:
                // Ignore these
                self.state = .active(state)
                return .noMessage
            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "connection", violation: "Unexpected inbound message: \(message)")
            }

            self.state = .active(state)
            return .forwardToMultiplexer(message)

        case .receivedKexInitWhenActive(var state):
            // We've received a key exchange packet. We only expect the first two messages (key exchange and key exchange init) before
            // we have sent a reply.
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .keyExchange(let message):
                let result = try state.receiveKeyExchangeMessage(message)
                self.state = .receivedKexInitWhenActive(state)
                return result
            case .keyExchangeInit(let message):
                let result = try state.receiveKeyExchangeInitMessage(message)
                self.state = .receivedKexInitWhenActive(state)
                return result
            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect
            case .ignore, .debug:
                // Ignore these
                self.state = .receivedKexInitWhenActive(state)
                return .noMessage
            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)
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
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Unexpected message: \(message)")
            }

        case .sentKexInitWhenActive(var state):
            // We've sent a key exchange packet. We expect channel messages _or_ a kexinit packet.
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .keyExchange(let message):
                let result = try state.receiveKeyExchangeMessage(message)
                self.state = .rekeying(.init(state))
                return result

            case .channelOpen(let message):
                try state.receiveChannelOpen(message)
            case .channelOpenConfirmation(let message):
                try state.receiveChannelOpenConfirmation(message)
            case .channelOpenFailure(let message):
                try state.receiveChannelOpenFailure(message)
            case .channelEOF(let message):
                try state.receiveChannelEOF(message)
            case .channelClose(let message):
                try state.receiveChannelClose(message)
            case .channelWindowAdjust(let message):
                try state.receiveChannelWindowAdjust(message)
            case .channelData(let message):
                try state.receiveChannelData(message)
            case .channelExtendedData(let message):
                try state.receiveChannelExtendedData(message)
            case .channelRequest(let message):
                try state.receiveChannelRequest(message)
            case .channelSuccess(let message):
                try state.receiveChannelSuccess(message)
            case .channelFailure(let message):
                try state.receiveChannelFailure(message)
            case .globalRequest(let message):
                try state.receiveGlobalRequest(message)
                self.state = .sentKexInitWhenActive(state)
                return .globalRequest(message)
            case .requestSuccess(let message):
                try state.receiveRequestSuccess(message)
                self.state = .sentKexInitWhenActive(state)
                return .globalRequestResponse(.success(message))
            case .requestFailure:
                try state.receiveRequestFailure()
                self.state = .sentKexInitWhenActive(state)
                return .globalRequestResponse(.failure)
            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect
            case .ignore, .debug:
                // Ignore these
                self.state = .sentKexInitWhenActive(state)
                return .noMessage
            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "connection", violation: "Unexpected inbound message: \(message)")
            }

            self.state = .sentKexInitWhenActive(state)
            return .forwardToMultiplexer(message)

        case .rekeying(var state):
            // This is basically the regular key exchange state.
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .keyExchange(let message):
                let result = try state.receiveKeyExchangeMessage(message)
                self.state = .rekeying(state)
                return result
            case .keyExchangeInit(let message):
                let result = try state.receiveKeyExchangeInitMessage(message)
                self.state = .rekeying(state)
                return result
            case .keyExchangeReply(let message):
                let result = try state.receiveKeyExchangeReplyMessage(message)
                self.state = .rekeying(state)
                return result
            case .newKeys:
                try state.receiveNewKeysMessage()
                let newState = RekeyingReceivedNewKeysState(state)
                self.state = .rekeyingReceivedNewKeysState(newState)
                return .noMessage
            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect
            case .ignore, .debug:
                // Ignore these
                self.state = .rekeying(state)
                return .noMessage
            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)
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
                throw NIOSSHError.protocolViolation(protocolName: "user auth", violation: "Unexpected user auth message: \(message)")
            }

        case .rekeyingReceivedNewKeysState(var state):
            // This is basically a regular active state.
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            // TODO(cory): One day soon we'll need to support re-keying in this state.
            // For now we only support channel messages.
            case .channelOpen(let message):
                try state.receiveChannelOpen(message)
            case .channelOpenConfirmation(let message):
                try state.receiveChannelOpenConfirmation(message)
            case .channelOpenFailure(let message):
                try state.receiveChannelOpenFailure(message)
            case .channelEOF(let message):
                try state.receiveChannelEOF(message)
            case .channelClose(let message):
                try state.receiveChannelClose(message)
            case .channelWindowAdjust(let message):
                try state.receiveChannelWindowAdjust(message)
            case .channelData(let message):
                try state.receiveChannelData(message)
            case .channelExtendedData(let message):
                try state.receiveChannelExtendedData(message)
            case .channelRequest(let message):
                try state.receiveChannelRequest(message)
            case .channelSuccess(let message):
                try state.receiveChannelSuccess(message)
            case .channelFailure(let message):
                try state.receiveChannelFailure(message)
            case .globalRequest(let message):
                try state.receiveGlobalRequest(message)
                self.state = .rekeyingReceivedNewKeysState(state)
                return .globalRequest(message)
            case .requestSuccess(let message):
                try state.receiveRequestSuccess(message)
                self.state = .rekeyingReceivedNewKeysState(state)
                return .globalRequestResponse(.success(message))
            case .requestFailure:
                try state.receiveRequestFailure()
                self.state = .rekeyingReceivedNewKeysState(state)
                return .globalRequestResponse(.failure)
            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect
            case .ignore, .debug:
                // Ignore these
                self.state = .rekeyingReceivedNewKeysState(state)
                return .noMessage
            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "connection", violation: "Unexpected inbound message: \(message)")
            }

            self.state = .rekeyingReceivedNewKeysState(state)
            return .forwardToMultiplexer(message)

        case .rekeyingSentNewKeysState(var state):
            // This is key exchange state.
            guard let message = try state.parser.nextPacket() else {
                return nil
            }

            switch message {
            case .keyExchange(let message):
                let result = try state.receiveKeyExchangeMessage(message)
                self.state = .rekeyingSentNewKeysState(state)
                return result
            case .keyExchangeInit(let message):
                let result = try state.receiveKeyExchangeInitMessage(message)
                self.state = .rekeyingSentNewKeysState(state)
                return result
            case .keyExchangeReply(let message):
                let result = try state.receiveKeyExchangeReplyMessage(message)
                self.state = .rekeyingSentNewKeysState(state)
                return result
            case .newKeys:
                try state.receiveNewKeysMessage()
                let newState = ActiveState(state)
                self.state = .active(newState)
                return .noMessage
            case .disconnect:
                self.state = .receivedDisconnect(state.role)
                return .disconnect
            case .ignore, .debug:
                // Ignore these
                self.state = .rekeyingSentNewKeysState(state)
                return .noMessage
            case .unimplemented(let unimplemented):
                throw NIOSSHError.remotePeerDoesNotSupportMessage(unimplemented)

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
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Unexpected message: \(message)")
            }

        case .receivedDisconnect, .sentDisconnect:
            // We do no further I/O in these states.
            return nil
        }
    }

    mutating func processOutboundMessage(_ message: SSHMessage,
                                         buffer: inout ByteBuffer,
                                         allocator: ByteBufferAllocator,
                                         loop: EventLoop) throws {
        switch self.state {
        case .idle(var state):
            switch message {
            case .version:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentVersion(.init(idleState: state, allocator: allocator))
            case .disconnect:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(state.role)
            case .ignore, .debug, .unimplemented:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .idle(state)
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
                try kex.writeKeyExchangeMessage(keyExchangeMessage, into: &buffer)
                self.state = .keyExchange(kex)
            case .keyExchangeInit(let kexInit):
                try kex.writeKeyExchangeInitMessage(kexInit, into: &buffer)
                self.state = .keyExchange(kex)
            case .keyExchangeReply(let kexReply):
                try kex.writeKeyExchangeReplyMessage(kexReply, into: &buffer)
                self.state = .keyExchange(kex)
            case .newKeys:
                try kex.writeNewKeysMessage(into: &buffer)
                let newState = SentNewKeysState(keyExchangeState: kex, loop: loop)
                let possibleMessage = newState.userAuthStateMachine.beginAuthentication()
                self.state = .sentNewKeys(newState)

                // If we have a service request message, re-spin the state machine to process that too.
                if let additionalMessage = possibleMessage {
                    try self.processOutboundMessage(.serviceRequest(additionalMessage), buffer: &buffer, allocator: allocator, loop: loop)
                }

            case .disconnect:
                try kex.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(kex.role)

            case .ignore, .debug, .unimplemented:
                try kex.serializer.serialize(message: message, to: &buffer)
                self.state = .keyExchange(kex)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Sent unexpected message type: \(message)")
            }

        case .receivedNewKeys(var kex):
            switch message {
            case .keyExchange(let keyExchangeMessage):
                try kex.writeKeyExchangeMessage(keyExchangeMessage, into: &buffer)
                self.state = .receivedNewKeys(kex)
            case .keyExchangeInit(let kexInit):
                try kex.writeKeyExchangeInitMessage(kexInit, into: &buffer)
                self.state = .receivedNewKeys(kex)
            case .keyExchangeReply(let kexReply):
                try kex.writeKeyExchangeReplyMessage(kexReply, into: &buffer)
                self.state = .receivedNewKeys(kex)
            case .newKeys:
                try kex.writeNewKeysMessage(into: &buffer)

                let newState = UserAuthenticationState(receivedNewKeysState: kex)
                let possibleMessage = newState.userAuthStateMachine.beginAuthentication()
                self.state = .userAuthentication(newState)

                // If we have a service request message, re-spin the state machine to process that too.
                if let additionalMessage = possibleMessage {
                    try self.processOutboundMessage(.serviceRequest(additionalMessage), buffer: &buffer, allocator: allocator, loop: loop)
                }

            case .disconnect:
                try kex.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(kex.role)

            case .ignore, .debug, .unimplemented:
                try kex.serializer.serialize(message: message, to: &buffer)
                self.state = .receivedNewKeys(kex)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Sent unexpected message type: \(message)")
            }

        case .sentNewKeys(var state):
            // In this state we tolerate sending service request. As we cannot have received any user auth messages
            // (we're still waiting for newKeys), we cannot possibly send any other user auth message
            switch message {
            case .serviceRequest(let message):
                try state.writeServiceRequest(message, into: &buffer)
                self.state = .sentNewKeys(state)

            case .serviceAccept, .userAuthRequest, .userAuthSuccess, .userAuthFailure:
                throw NIOSSHError.protocolViolation(protocolName: "user auth", violation: "Cannot send \(message) before receiving newKeys")

            case .disconnect:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(state.role)

            case .ignore, .debug, .unimplemented:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentNewKeys(state)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "user auth", violation: "Sent unexpected message type: \(message)")
            }

        case .userAuthentication(var state):
            // In this state we tolerate sending user auth messages.
            switch message {
            case .serviceRequest(let message):
                try state.writeServiceRequest(message, into: &buffer)
                self.state = .userAuthentication(state)

            case .serviceAccept(let message):
                try state.writeServiceAccept(message, into: &buffer)
                self.state = .userAuthentication(state)

            case .userAuthRequest(let message):
                try state.writeUserAuthRequest(message, into: &buffer)
                self.state = .userAuthentication(state)

            case .userAuthSuccess:
                try state.writeUserAuthSuccess(into: &buffer)
                // Ok we're good to go!
                self.state = .active(ActiveState(state))

            case .userAuthFailure(let message):
                try state.writeUserAuthFailure(message, into: &buffer)
                self.state = .userAuthentication(state)

            case .userAuthPKOK(let message):
                try state.writeUserAuthPKOK(message, into: &buffer)
                self.state = .userAuthentication(state)

            case .disconnect:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(state.role)

            case .ignore, .debug, .unimplemented:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .userAuthentication(state)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "user auth", violation: "Sent unexpected message type: \(message)")
            }

        case .active(var state):
            switch message {
            case .channelOpen(let message):
                try state.writeChannelOpen(message, into: &buffer)
            case .channelOpenConfirmation(let message):
                try state.writeChannelOpenConfirmation(message, into: &buffer)
            case .channelOpenFailure(let message):
                try state.writeChannelOpenFailure(message, into: &buffer)
            case .channelEOF(let message):
                try state.writeChannelEOF(message, into: &buffer)
            case .channelClose(let message):
                try state.writeChannelClose(message, into: &buffer)
            case .channelWindowAdjust(let message):
                try state.writeChannelWindowAdjust(message, into: &buffer)
            case .channelData(let message):
                try state.writeChannelData(message, into: &buffer)
            case .channelExtendedData(let message):
                try state.writeChannelExtendedData(message, into: &buffer)
            case .channelRequest(let message):
                try state.writeChannelRequest(message, into: &buffer)
            case .channelSuccess(let message):
                try state.writeChannelSuccess(message, into: &buffer)
            case .channelFailure(let message):
                try state.writeChannelFailure(message, into: &buffer)
            case .globalRequest(let message):
                try state.writeGlobalRequest(message, into: &buffer)
            case .requestSuccess(let message):
                try state.writeRequestSuccess(message, into: &buffer)
            case .requestFailure:
                try state.writeRequestFailure(into: &buffer)
            case .disconnect:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(state.role)
                return
            case .ignore, .debug, .unimplemented:
                try state.serializer.serialize(message: message, to: &buffer)
            default:
                throw NIOSSHError.protocolViolation(protocolName: "connection", violation: "Sent unexpected message type: \(message)")
            }

            self.state = .active(state)

        case .receivedKexInitWhenActive(var state):
            // In this state we only allow sending key exchange messages. In particular, the key exchange message is the only allowed one.
            switch message {
            case .keyExchange(let keyExchangeMessage):
                try state.writeKeyExchangeMessage(keyExchangeMessage, into: &buffer)
                self.state = .rekeying(.init(state))

            case .disconnect:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(state.role)

            case .ignore, .debug, .unimplemented:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .receivedKexInitWhenActive(state)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Sent unexpected message type: \(message)")
            }

        case .sentKexInitWhenActive(var state):
            // In this state we've send a key exchange init message, but not received one from the peer. We have nothing to send.
            switch message {
            case .disconnect:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(state.role)

            case .ignore, .debug, .unimplemented:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentKexInitWhenActive(state)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Sent unexpected message type: \(message)")
            }

        case .rekeying(var state):
            // This is a full key exchange state.
            switch message {
            case .keyExchange(let keyExchangeMessage):
                try state.writeKeyExchangeMessage(keyExchangeMessage, into: &buffer)
                self.state = .rekeying(state)
            case .keyExchangeInit(let kexInit):
                try state.writeKeyExchangeInitMessage(kexInit, into: &buffer)
                self.state = .rekeying(state)
            case .keyExchangeReply(let kexReply):
                try state.writeKeyExchangeReplyMessage(kexReply, into: &buffer)
                self.state = .rekeying(state)
            case .newKeys:
                try state.writeNewKeysMessage(into: &buffer)
                self.state = .rekeyingSentNewKeysState(.init(state))

            case .disconnect:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(state.role)

            case .ignore, .debug, .unimplemented:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .rekeying(state)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Sent unexpected message type: \(message)")
            }

        case .rekeyingReceivedNewKeysState(var state):
            // We may be doing any part of key exchange still.
            switch message {
            case .keyExchange(let keyExchangeMessage):
                try state.writeKeyExchangeMessage(keyExchangeMessage, into: &buffer)
                self.state = .rekeyingReceivedNewKeysState(state)
            case .keyExchangeInit(let kexInit):
                try state.writeKeyExchangeInitMessage(kexInit, into: &buffer)
                self.state = .rekeyingReceivedNewKeysState(state)
            case .keyExchangeReply(let kexReply):
                try state.writeKeyExchangeReplyMessage(kexReply, into: &buffer)
                self.state = .rekeyingReceivedNewKeysState(state)
            case .newKeys:
                try state.writeNewKeysMessage(into: &buffer)
                self.state = .active(.init(state))

            case .disconnect:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(state.role)

            case .ignore, .debug, .unimplemented:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .rekeyingReceivedNewKeysState(state)

            default:
                throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "Sent unexpected message type: \(message)")
            }

        case .rekeyingSentNewKeysState(var state):
            // We can send channel messages again.
            switch message {
            case .channelOpen(let message):
                try state.writeChannelOpen(message, into: &buffer)
            case .channelOpenConfirmation(let message):
                try state.writeChannelOpenConfirmation(message, into: &buffer)
            case .channelOpenFailure(let message):
                try state.writeChannelOpenFailure(message, into: &buffer)
            case .channelEOF(let message):
                try state.writeChannelEOF(message, into: &buffer)
            case .channelClose(let message):
                try state.writeChannelClose(message, into: &buffer)
            case .channelWindowAdjust(let message):
                try state.writeChannelWindowAdjust(message, into: &buffer)
            case .channelData(let message):
                try state.writeChannelData(message, into: &buffer)
            case .channelExtendedData(let message):
                try state.writeChannelExtendedData(message, into: &buffer)
            case .channelRequest(let message):
                try state.writeChannelRequest(message, into: &buffer)
            case .channelSuccess(let message):
                try state.writeChannelSuccess(message, into: &buffer)
            case .channelFailure(let message):
                try state.writeChannelFailure(message, into: &buffer)
            case .globalRequest(let message):
                try state.writeGlobalRequest(message, into: &buffer)
            case .requestSuccess(let message):
                try state.writeRequestSuccess(message, into: &buffer)
            case .requestFailure:
                try state.writeRequestFailure(into: &buffer)
            case .disconnect:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .sentDisconnect(state.role)
                return
            case .ignore, .debug, .unimplemented:
                try state.serializer.serialize(message: message, to: &buffer)
                self.state = .rekeyingSentNewKeysState(state)
            default:
                throw NIOSSHError.protocolViolation(protocolName: "connection", violation: "Sent unexpected message type: \(message)")
            }

            self.state = .rekeyingSentNewKeysState(state)

        case .sentDisconnect, .receivedDisconnect:
            // We don't allow more messages once disconnect has occured
            throw NIOSSHError.protocolViolation(protocolName: "transport", violation: "I/O after disconnect")
        }
    }
}

extension SSHConnectionStateMachine {
    /// The result of spinning the state machine with an inbound message.
    ///
    /// When the state machine processes a message, several things may happen. Firstly, it may generate an
    /// automatic message that should be sent. Secondly, it may generate a possibility of having a message in
    /// future. Thirdly, it may be a message targetted to one of the child channels. Fourthly, it may require us to disconnect.
    /// Fifthly, it may generate nothing.
    enum StateMachineInboundProcessResult {
        case emitMessage(SSHMultiMessage)
        case possibleFutureMessage(EventLoopFuture<SSHMultiMessage?>)
        case forwardToMultiplexer(SSHMessage)
        case globalRequestResponse(GlobalRequestResponse)
        case globalRequest(SSHMessage.GlobalRequestMessage)
        case disconnect
        case noMessage
        case event(Any)

        enum GlobalRequestResponse {
            case success(SSHMessage.RequestSuccessMessage)
            case failure
        }
    }
}

// MARK: Rekeying

extension SSHConnectionStateMachine {
    // Called when we wish to re-key the connection.
    mutating func beginRekeying(buffer: inout ByteBuffer, allocator: ByteBufferAllocator, loop: EventLoop) throws {
        switch self.state {
        case .active(let state):
            // Trying to rekey.
            var newState = SentKexInitWhenActiveState(state, allocator: allocator, loop: loop)
            let message = newState.keyExchangeStateMachine.createKeyExchangeMessage()
            try newState.writeKeyExchangeMessage(message, into: &buffer)
            self.state = .sentKexInitWhenActive(newState)
            return
        case .idle, .sentVersion, .keyExchange, .receivedNewKeys, .sentNewKeys, .userAuthentication,
             .receivedKexInitWhenActive, .sentKexInitWhenActive, .rekeying, .rekeyingReceivedNewKeysState,
             .rekeyingSentNewKeysState, .receivedDisconnect, .sentDisconnect:
            preconditionFailure("May not rekey in this state: \(self.state)")
        }
    }
}

// MARK: Helper properties

extension SSHConnectionStateMachine {
    var isActive: Bool {
        switch self.state {
        case .active:
            return true
        case .idle, .sentVersion, .keyExchange, .receivedNewKeys, .sentNewKeys, .userAuthentication,
             .receivedKexInitWhenActive, .sentKexInitWhenActive, .rekeying, .rekeyingReceivedNewKeysState,
             .rekeyingSentNewKeysState, .receivedDisconnect, .sentDisconnect:
            return false
        }
    }

    var disconnected: Bool {
        switch self.state {
        case .receivedDisconnect, .sentDisconnect:
            return true
        case .idle, .sentVersion, .keyExchange, .receivedNewKeys, .sentNewKeys, .userAuthentication, .active,
             .receivedKexInitWhenActive, .sentKexInitWhenActive, .rekeying, .rekeyingReceivedNewKeysState,
             .rekeyingSentNewKeysState:
            return false
        }
    }

    /// Like `isActive`, but covers all states past `.active`.
    var hasActivated: Bool {
        switch self.state {
        case .active, .receivedKexInitWhenActive, .sentKexInitWhenActive, .rekeying, .rekeyingReceivedNewKeysState,
             .rekeyingSentNewKeysState, .receivedDisconnect, .sentDisconnect:
            return true
        case .idle, .sentVersion, .keyExchange, .receivedNewKeys, .sentNewKeys, .userAuthentication:
            return false
        }
    }

    var role: SSHConnectionRole {
        switch self.state {
        case .idle(let state):
            return state.role
        case .sentVersion(let state):
            return state.role
        case .keyExchange(let state):
            return state.role
        case .receivedNewKeys(let state):
            return state.role
        case .sentNewKeys(let state):
            return state.role
        case .userAuthentication(let state):
            return state.role
        case .active(let state):
            return state.role
        case .receivedKexInitWhenActive(let state):
            return state.role
        case .sentKexInitWhenActive(let state):
            return state.role
        case .rekeying(let state):
            return state.role
        case .rekeyingReceivedNewKeysState(let state):
            return state.role
        case .rekeyingSentNewKeysState(let state):
            return state.role
        case .receivedDisconnect(let role):
            return role
        case .sentDisconnect(let role):
            return role
        }
    }
}
