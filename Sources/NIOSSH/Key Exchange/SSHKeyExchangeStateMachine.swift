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

struct SSHKeyExchangeStateMachine {
    enum SSHKeyExchangeError: Error {
        case unexpectedMessage
        case inconsistentState
    }

    enum State {
        /// Key exchange has not begun yet.
        case idle

        /// We've sent our key exchange message.
        ///
        /// Either clients or servers can send this message: they are entitled to race. Thus, either
        /// party can enter this state.
        ///
        /// We store the message we sent for later.
        case keyExchangeSent(message: SSHMessage.KeyExchangeMessage)

        /// We've received a key exchange message.
        ///
        /// Either clients or servers can send this message: they are entitled to race. Thus, either
        /// party can enter this state. The remote peer may be sending a guess as well.
        ///
        /// We store the message we sent for later.
        case keyExchangeReceived(exchange: Curve25519KeyExchange, negotiated: NegotiationResult, expectingGuess: Bool)

        /// The peer has guessed what key exchange init packet is coming, and guessed wrong. We need to wait for them to send that packet.
        case awaitingKeyExchangeInitInvalidGuess(exchange: Curve25519KeyExchange, negotiated: NegotiationResult)

        /// Both sides have sent their initial key exchange message but we have not begun actually performing a key exchange.
        case awaitingKeyExchangeInit(exchange: Curve25519KeyExchange, negotiated: NegotiationResult)

        /// We've received the key exchange init, but not sent our reply yet.
        case keyExchangeInitReceived(result: KeyExchangeResult, negotiated: NegotiationResult)

        /// We've sent our keyExchangeInit, but not received the keyExchangeReply.
        case keyExchangeInitSent(exchange: Curve25519KeyExchange, negotiated: NegotiationResult)

        /// The keys have been exchanged.
        case keysExchanged(result: KeyExchangeResult, protection: NIOSSHTransportProtection, negotiated: NegotiationResult)

        /// We have received the remote peer's newKeys message, and are waiting to send our own.
        case newKeysReceived(result: KeyExchangeResult, protection: NIOSSHTransportProtection, negotiated: NegotiationResult)

        /// We have sent our newKeys message, and are waiting to receive the remote peer's.
        case newKeysSent(result: KeyExchangeResult, protection: NIOSSHTransportProtection, negotiated: NegotiationResult)

        /// We've completed the key exchange.
        case complete(result: KeyExchangeResult)
    }

    private let allocator: ByteBufferAllocator
    private let role: SSHConnectionRole
    private var state: State
    private var initialExchangeBytes: ByteBuffer
    private var protectionSchemes: [NIOSSHTransportProtection.Type]
    private var previousSessionIdentifier: ByteBuffer?

    init(allocator: ByteBufferAllocator, role: SSHConnectionRole, remoteVersion: String, protectionSchemes: [NIOSSHTransportProtection.Type], previousSessionIdentifier: ByteBuffer?) {
        self.allocator = allocator
        self.role = role
        self.initialExchangeBytes = allocator.buffer(capacity: 1024)
        self.state = .idle
        self.protectionSchemes = protectionSchemes
        self.previousSessionIdentifier = previousSessionIdentifier

        switch self.role {
        case .client:
            self.initialExchangeBytes.writeSSHString(Constants.version.utf8)
            self.initialExchangeBytes.writeSSHString(remoteVersion.utf8)
        case .server:
            self.initialExchangeBytes.writeSSHString(remoteVersion.utf8)
            self.initialExchangeBytes.writeSSHString(Constants.version.utf8)
        }
    }

    /// Currently we statically only use a single key exchange message. In future this will expand out to
    /// support arbitrary SSHTransportProtection schemes.
    func createKeyExchangeMessage() -> SSHMessage.KeyExchangeMessage {
        var rng = CSPRNG()

        let encryptionAlgorithms = self.supportedEncryptionAlgorithms
        let macAlgorithms = self.supportedMacAlgorithms

        return .init(
            cookie: rng.randomCookie(allocator: self.allocator),
            keyExchangeAlgorithms: Self.supportedKeyExchangeAlgorithms,
            serverHostKeyAlgorithms: self.supportedHostKeyAlgorithms,
            encryptionAlgorithmsClientToServer: encryptionAlgorithms,
            encryptionAlgorithmsServerToClient: encryptionAlgorithms,
            macAlgorithmsClientToServer: macAlgorithms,
            macAlgorithmsServerToClient: macAlgorithms,
            compressionAlgorithmsClientToServer: ["none"],
            compressionAlgorithmsServerToClient: ["none"],
            languagesClientToServer: [],
            languagesServerToClient: [],
            firstKexPacketFollows: false
        )
    }

    mutating func handle(keyExchange message: SSHMessage.KeyExchangeMessage) throws -> SSHMultiMessage? {
        switch self.state {
        case .keyExchangeSent(message: let ourMessage):
            switch self.role {
            case .client:
                self.addKeyExchangeInitMessagesToExchangeBytes(clientsMessage: ourMessage, serversMessage: message)

                // verify algorithms
                let negotiated = try self.negotiatedAlgorithms(message)
                let exchanger = self.exchangerForAlgorithm(negotiated.negotiatedKeyExchangeAlgorithm)

                // Ok, we need to send the key exchange message.
                let message = SSHMessage.keyExchangeInit(exchanger.initiateKeyExchangeClientSide(allocator: self.allocator))
                self.state = .awaitingKeyExchangeInit(exchange: exchanger, negotiated: negotiated)
                return SSHMultiMessage(message)
            case .server:
                // Write their message in first, then ours.
                self.addKeyExchangeInitMessagesToExchangeBytes(clientsMessage: message, serversMessage: ourMessage)

                let negotiated = try self.negotiatedAlgorithms(message)
                let exchanger = self.exchangerForAlgorithm(negotiated.negotiatedKeyExchangeAlgorithm)

                // Ok, we're waiting for them to go. They might be sending a wrong guess, which we want to ignore.
                if self.expectingIncorrectGuess(message) {
                    self.state = .awaitingKeyExchangeInitInvalidGuess(exchange: exchanger, negotiated: negotiated)
                } else {
                    self.state = .awaitingKeyExchangeInit(exchange: exchanger, negotiated: negotiated)
                }
                return nil
            }
        case .idle:
            // We received a key exchange message while idle. We will need to send our own key exchange message back,
            // and also follow immediately up with our own key exchange init message.
            let ourMessage = self.createKeyExchangeMessage()

            switch self.role {
            case .client:
                self.addKeyExchangeInitMessagesToExchangeBytes(clientsMessage: ourMessage, serversMessage: message)
            case .server:
                self.addKeyExchangeInitMessagesToExchangeBytes(clientsMessage: message, serversMessage: ourMessage)
            }

            let negotiated = try self.negotiatedAlgorithms(message)
            let exchanger = self.exchangerForAlgorithm(negotiated.negotiatedKeyExchangeAlgorithm)

            let result: SSHMultiMessage
            switch self.role {
            case .client:
                result = SSHMultiMessage(.keyExchange(ourMessage), SSHMessage.keyExchangeInit(exchanger.initiateKeyExchangeClientSide(allocator: self.allocator)))
            case .server:
                result = SSHMultiMessage(.keyExchange(ourMessage))
            }

            self.state = .keyExchangeReceived(exchange: exchanger, negotiated: negotiated, expectingGuess: self.expectingIncorrectGuess(message))
            return result

        case .keyExchangeReceived, .awaitingKeyExchangeInit, .awaitingKeyExchangeInitInvalidGuess, .keyExchangeInitReceived, .keyExchangeInitSent, .keysExchanged, .newKeysSent, .newKeysReceived, .complete:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func send(keyExchange message: SSHMessage.KeyExchangeMessage) {
        switch self.state {
        case .idle:
            self.state = .keyExchangeSent(message: message)
        case .keyExchangeReceived(let exchanger, let negotiated, let expectingGuess):
            switch self.role {
            case .server:
                // Ok, we're waiting for a key exchange init message.
                if expectingGuess {
                    self.state = .awaitingKeyExchangeInitInvalidGuess(exchange: exchanger, negotiated: negotiated)
                } else {
                    self.state = .awaitingKeyExchangeInit(exchange: exchanger, negotiated: negotiated)
                }

            case .client:
                // We're going to send a key exchange init message.
                self.state = .awaitingKeyExchangeInit(exchange: exchanger, negotiated: negotiated)
            }
        case .keyExchangeSent, .awaitingKeyExchangeInit, .awaitingKeyExchangeInitInvalidGuess, .keyExchangeInitReceived, .keyExchangeInitSent, .keysExchanged, .newKeysSent, .newKeysReceived, .complete:
            // This is a precondition not a throw because we control the sending of this message.
            preconditionFailure("Cannot send key exchange message after idle")
        }
    }

    mutating func handle(keyExchangeInit message: SSHMessage.KeyExchangeECDHInitMessage) throws -> SSHMultiMessage? {
        switch self.state {
        case .awaitingKeyExchangeInitInvalidGuess(exchange: let exchanger, negotiated: let negotiated):
            // We're going to ignore this one, we already know it's wrong.
            assert(self.role.isServer, "Clients cannot be expecting invalid guess from the peer")
            self.state = .awaitingKeyExchangeInit(exchange: exchanger, negotiated: negotiated)
            return nil

        case .awaitingKeyExchangeInit(exchange: var exchanger, negotiated: let negotiated):
            switch self.role {
            case .client:
                throw SSHKeyExchangeError.unexpectedMessage
            case .server(let configuration):
                let (result, reply) = try exchanger.completeKeyExchangeServerSide(
                    clientKeyExchangeMessage: message,
                    serverHostKey: negotiated.negotiatedHostKey(configuration.hostKeys),
                    initialExchangeBytes: &self.initialExchangeBytes,
                    allocator: self.allocator, expectedKeySizes: negotiated.negotiatedProtection.keySizes
                )

                let message = SSHMessage.keyExchangeReply(reply)
                self.state = .keyExchangeInitReceived(result: result, negotiated: negotiated)
                return SSHMultiMessage(message, .newKeys)
            }
        case .idle, .keyExchangeSent, .keyExchangeReceived, .keyExchangeInitReceived, .keyExchangeInitSent, .keysExchanged, .newKeysSent, .newKeysReceived, .complete:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func send(keyExchangeInit message: SSHMessage.KeyExchangeECDHInitMessage) {
        switch self.state {
        case .awaitingKeyExchangeInit(exchange: let exchanger, negotiated: let negotiated):
            precondition(self.role.isClient, "Servers must not send ecdh key exchange init messages")
            self.state = .keyExchangeInitSent(exchange: exchanger, negotiated: negotiated)
        case .idle, .keyExchangeSent, .keyExchangeReceived, .awaitingKeyExchangeInitInvalidGuess, .keyExchangeInitSent, .keyExchangeInitReceived, .keysExchanged, .newKeysSent, .newKeysReceived, .complete:
            // This is a precondition not a throw because we control the sending of this message.
            preconditionFailure("Cannot send ECDH key exchange message in state \(self.state)")
        }
    }

    mutating func handle(keyExchangeReply message: SSHMessage.KeyExchangeECDHReplyMessage) throws -> SSHMultiMessage {
        switch self.state {
        case .keyExchangeInitSent(exchange: var exchanger, negotiated: let negotiated):
            switch self.role {
            case .client:
                let result = try exchanger.receiveServerKeyExchangePayload(
                    serverKeyExchangeMessage: message,
                    initialExchangeBytes: &self.initialExchangeBytes,
                    allocator: self.allocator,
                    expectedKeySizes: negotiated.negotiatedProtection.keySizes
                )

                self.state = .keysExchanged(result: result, protection: try negotiated.negotiatedProtection.init(initialKeys: result.keys), negotiated: negotiated)
                return SSHMultiMessage(SSHMessage.newKeys)
            case .server:
                preconditionFailure("Servers cannot enter key exchange init sent.")
            }
        case .idle, .keyExchangeSent, .keyExchangeReceived, .awaitingKeyExchangeInit, .awaitingKeyExchangeInitInvalidGuess, .keyExchangeInitReceived, .keysExchanged, .newKeysSent, .newKeysReceived, .complete:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func send(keyExchangeReply message: SSHMessage.KeyExchangeECDHReplyMessage) throws {
        switch self.state {
        case .keyExchangeInitReceived(result: let result, negotiated: let negotiated):
            precondition(self.role.isServer, "Clients cannot enter key exchange init received")
            self.state = .keysExchanged(result: result, protection: try negotiated.negotiatedProtection.init(initialKeys: result.keys), negotiated: negotiated)
        case .idle, .keyExchangeSent, .keyExchangeReceived, .awaitingKeyExchangeInit, .awaitingKeyExchangeInitInvalidGuess, .keyExchangeInitSent, .keysExchanged, .newKeysSent, .newKeysReceived, .complete:
            // This is a precondition not a throw because we control the sending of this message.
            preconditionFailure("Cannot send ECDH key exchange message in state \(self.state)")
        }
    }

    mutating func handleNewKeys() throws -> NIOSSHTransportProtection {
        switch self.state {
        case .keysExchanged(result: let result, protection: let protection, negotiated: let negotiated):
            self.state = .newKeysReceived(result: result, protection: protection, negotiated: negotiated)
            return protection
        case .newKeysSent(result: let result, protection: let protection, _):
            self.state = .complete(result: result)
            return protection
        case .idle, .keyExchangeSent, .keyExchangeReceived, .awaitingKeyExchangeInit, .awaitingKeyExchangeInitInvalidGuess, .keyExchangeInitSent, .keyExchangeInitReceived, .newKeysReceived, .complete:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func sendNewKeys() -> NIOSSHTransportProtection {
        switch self.state {
        case .keysExchanged(result: let result, protection: let protection, negotiated: let negotiated):
            self.state = .newKeysSent(result: result, protection: protection, negotiated: negotiated)
            return protection
        case .newKeysReceived(result: let result, protection: let protection, _):
            self.state = .complete(result: result)
            return protection
        case .idle, .keyExchangeSent, .keyExchangeReceived, .awaitingKeyExchangeInit, .awaitingKeyExchangeInitInvalidGuess, .keyExchangeInitSent, .keyExchangeInitReceived, .newKeysSent, .complete:
            // This is a precondition not a throw because we control the sending of this message.
            preconditionFailure("Cannot send ECDH key exchange message in state \(self.state)")
        }
    }

    private func negotiatedAlgorithms(_ message: SSHMessage.KeyExchangeMessage) throws -> NegotiationResult {
        let (keyExchange, hostKey) = try self.negotiatedKeyExchangeAlgorithm(peerKeyExchangeAlgorithms: message.keyExchangeAlgorithms,
                                                                             peerHostKeyAlgorithms: message.serverHostKeyAlgorithms)
        let (clientEncryption, clientMAC) = try self.negotiatedTransportProtection(peerEncryptionAlgorithms: message.encryptionAlgorithmsClientToServer, peerMacAlgorithms: message.macAlgorithmsClientToServer)
        let (serverEncryption, serverMAC) = try self.negotiatedTransportProtection(peerEncryptionAlgorithms: message.encryptionAlgorithmsServerToClient, peerMacAlgorithms: message.macAlgorithmsServerToClient)

        // We only support symmetrical negotiation results.
        guard clientEncryption == serverEncryption, clientMAC == serverMAC else {
            throw NIOSSHError.keyExchangeNegotiationFailure
        }

        // Ok, now we need to find the right transport protection scheme. This can technically fail.
        guard let scheme = self.protectionSchemes.first(where: { $0.cipherName == clientEncryption && ($0.macName == nil || $0.macName! == clientMAC) }) else {
            throw NIOSSHError.keyExchangeNegotiationFailure
        }

        // Great, we have a protection scheme. Build the negotiation result.
        return NegotiationResult(negotiatedKeyExchangeAlgorithm: keyExchange, negotiatedHostKeyAlgorithm: hostKey, negotiatedProtection: scheme)
    }

    private func negotiatedKeyExchangeAlgorithm(peerKeyExchangeAlgorithms: [Substring], peerHostKeyAlgorithms: [Substring]) throws -> (keyExchange: Substring, hostKey: Substring) {
        // From RFC 4253:
        //
        // > The first algorithm MUST be the preferred (and guessed) algorithm.  If
        // > both sides make the same guess, that algorithm MUST be used.
        // > Otherwise, the following algorithm MUST be used to choose a key
        // > exchange method: Iterate over client's kex algorithms, one at a
        // > time.  Choose the first algorithm that satisfies the following
        // > conditions:
        // >
        // > +  the server also supports the algorithm,
        // >
        // > +  if the algorithm requires an encryption-capable host key,
        // >    there is an encryption-capable algorithm on the server's
        // >    server_host_key_algorithms that is also supported by the
        // >    client, and
        // >
        // > +  if the algorithm requires a signature-capable host key,
        // >    there is a signature-capable algorithm on the server's
        // >    server_host_key_algorithms that is also supported by the
        // >    client.
        // >
        // > If no algorithm satisfying all these conditions can be found, the
        // > connection fails, and both sides MUST disconnect.

        // Ok, rephrase as client and server instead of us and them.
        let clientAlgorithms: [Substring]
        let serverAlgorithms: [Substring]
        let supportedHostKeyAlgorithms = self.supportedHostKeyAlgorithms

        switch self.role {
        case .client:
            clientAlgorithms = Self.supportedKeyExchangeAlgorithms
            serverAlgorithms = peerKeyExchangeAlgorithms
        case .server:
            clientAlgorithms = peerKeyExchangeAlgorithms
            serverAlgorithms = Self.supportedKeyExchangeAlgorithms
        }

        // Let's find the first protocol the client supports that the server does too.
        for algorithm in clientAlgorithms {
            guard serverAlgorithms.contains(algorithm) else {
                continue
            }

            // Ok, got one. We need a signing capable host key algorithm, which for us is all of them.
            // We iterate over our list because it's almost certainly smaller than the peer's.
            for hostKeyAlgorithm in supportedHostKeyAlgorithms {
                guard peerHostKeyAlgorithms.contains(hostKeyAlgorithm) else {
                    continue
                }

                // Got one! This one works.
                return (keyExchange: algorithm, hostKey: hostKeyAlgorithm)
            }
        }

        // Completed the loop with usable protocols, we have to throw.
        throw NIOSSHError.keyExchangeNegotiationFailure
    }

    private func negotiatedTransportProtection(peerEncryptionAlgorithms: [Substring], peerMacAlgorithms: [Substring]) throws -> (encryption: Substring, mac: Substring) {
        // Ok, rephrase as client and server instead of us and them.
        let clientEncryptionAlgorithms: [Substring]
        let serverEncryptionAlgorithms: [Substring]
        let clientMACAlgorithms: [Substring]
        let serverMACAlgorithms: [Substring]

        switch self.role {
        case .client:
            clientEncryptionAlgorithms = self.supportedEncryptionAlgorithms
            clientMACAlgorithms = self.supportedMacAlgorithms
            serverEncryptionAlgorithms = peerEncryptionAlgorithms
            serverMACAlgorithms = peerMacAlgorithms
        case .server:
            clientEncryptionAlgorithms = peerEncryptionAlgorithms
            clientMACAlgorithms = peerMacAlgorithms
            serverEncryptionAlgorithms = self.supportedEncryptionAlgorithms
            serverMACAlgorithms = self.supportedMacAlgorithms
        }

        // Ok, the algorithm is that we choose the first encryption and MAC algorithm in the client's list that
        // is in the server's list as well.
        guard let encryption = clientEncryptionAlgorithms.first(where: { serverEncryptionAlgorithms.contains($0) }) else {
            throw NIOSSHError.keyExchangeNegotiationFailure
        }

        // Ok great, now work out what we negotiated as a MAC.
        guard let mac = clientMACAlgorithms.first(where: { serverMACAlgorithms.contains($0) }) else {
            throw NIOSSHError.keyExchangeNegotiationFailure
        }

        return (encryption, mac)
    }

    private mutating func addKeyExchangeInitMessagesToExchangeBytes(clientsMessage: SSHMessage.KeyExchangeMessage, serversMessage: SSHMessage.KeyExchangeMessage) {
        // Write the client's bytes to the exchange bytes first.
        self.initialExchangeBytes.writeCompositeSSHString { buffer in
            buffer.writeSSHMessage(.keyExchange(clientsMessage))
        }

        self.initialExchangeBytes.writeCompositeSSHString { buffer in
            buffer.writeSSHMessage(.keyExchange(serversMessage))
        }
    }

    private func exchangerForAlgorithm(_ algorithm: Substring) -> Curve25519KeyExchange {
        assert(Self.supportedKeyExchangeAlgorithms.contains(algorithm))
        // We only support Curve25519 right now, so we up this to a precondition.
        precondition(Self.supportedKeyExchangeAlgorithms.contains(algorithm))
        return Curve25519KeyExchange(ourRole: self.role, previousSessionIdentifier: self.previousSessionIdentifier)
    }

    private func expectingIncorrectGuess(_ kexMessage: SSHMessage.KeyExchangeMessage) -> Bool {
        // A guess is wrong if the key exchange algorithm and/or the host key algorithm differ from our preference.
        kexMessage.firstKexPacketFollows && (
            kexMessage.keyExchangeAlgorithms.first != Self.supportedKeyExchangeAlgorithms.first ||
                kexMessage.serverHostKeyAlgorithms.first != self.supportedHostKeyAlgorithms.first
        )
    }

    // The host key algorithms supported by this peer, in order of preference.
    private var supportedHostKeyAlgorithms: [Substring] {
        switch self.role {
        case .client:
            return Self.supportedServerHostKeyAlgorithms
        case .server(let configuration):
            return configuration.hostKeys.flatMap { $0.hostKeyAlgorithms }
        }
    }

    /// The encryption algorithms supported by this peer, in order of preference.
    private var supportedEncryptionAlgorithms: [Substring] {
        self.protectionSchemes.map { Substring($0.cipherName) }
    }

    /// The MAC algorithms supported by this peer, in order of preference.
    private var supportedMacAlgorithms: [Substring] {
        let schemes = self.protectionSchemes.compactMap { $0.macName.map { Substring($0) } }

        // We do a weird thing here: if there are no MAC schemes, we lie and put one in. This is
        // because some schemes (such as AES-GCM in OpenSSH mode) ignore the MAC negotiation.
        // Worse case, we fail out later in the handshake because the peer actually wanted it.
        if schemes.isEmpty {
            return ["hmac-sha2-256"]
        } else {
            return schemes
        }
    }
}

extension SSHKeyExchangeStateMachine {
    // For now this is a static list.
    static let supportedKeyExchangeAlgorithms: [Substring] = ["curve25519-sha256", "curve25519-sha256@libssh.org"]

    /// All known host key algorithms.
    static let supportedServerHostKeyAlgorithms: [Substring] = ["ssh-ed25519", "ecdsa-sha2-nistp256"]
}

extension SSHKeyExchangeStateMachine {
    struct NegotiationResult {
        var negotiatedKeyExchangeAlgorithm: Substring

        var negotiatedHostKeyAlgorithm: Substring

        var negotiatedProtection: NIOSSHTransportProtection.Type

        func negotiatedHostKey(_ keys: [NIOSSHPrivateKey]) -> NIOSSHPrivateKey {
            // This force-unwrap is safe: to fail to obtain it is a programming error, as we must have negotiated
            // the host key algorithm.
            keys.first { $0.hostKeyAlgorithms.contains(self.negotiatedHostKeyAlgorithm) }!
        }
    }

    /// Obtains the session ID, if we have one already.
    var sessionID: ByteBuffer? {
        switch self.state {
        case .keyExchangeInitReceived(result: let result, _),
             .keysExchanged(result: let result, _, _),
             .newKeysSent(result: let result, _, _),
             .newKeysReceived(result: let result, _, _),
             .complete(result: let result):
            return result.sessionID

        case .idle, .keyExchangeSent, .keyExchangeReceived, .awaitingKeyExchangeInit, .awaitingKeyExchangeInitInvalidGuess, .keyExchangeInitSent:
            return nil
        }
    }
}

extension CSPRNG {
    /// A SSH key exchange cookie is 16 random bytes.
    fileprivate mutating func randomCookie(allocator: ByteBufferAllocator) -> ByteBuffer {
        var buffer = allocator.buffer(capacity: 16)
        buffer.writeInteger(self.next())
        buffer.writeInteger(self.next())
        assert(buffer.readableBytes == 16)
        return buffer
    }
}
