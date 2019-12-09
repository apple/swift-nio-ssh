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
        case unsupportedVersion
    }

    enum State {
        case idle
        case version
        case keyExchange
        case keyExchangeInit
        case newKeys(KeyExchangeResult)
    }

    private let allocator: ByteBufferAllocator
    private let role: SSHConnectionRole
    private var exhange: Curve25519KeyExchange
    private var state: State = .idle
    private var initialExchangeBytes: ByteBuffer

    init(allocator: ByteBufferAllocator, role: SSHConnectionRole) {
        self.allocator = allocator
        self.role = role
        self.initialExchangeBytes = allocator.buffer(capacity: 1024)
        self.exhange = Curve25519KeyExchange(ourRole: role, previousSessionIdentifier: nil)
    }

    mutating func start() throws -> SSHMessage? {
        switch self.state {
        case .idle:
            switch self.role {
            case .client:
                self.initialExchangeBytes.writeSSHString("SSH-2.0-SwiftNIOSSH_1.0".utf8)
                self.state = .version
                return nil
            case .server:
                let message = SSHMessage.version("SSH-2.0-SwiftNIOSSH_1.0")
                self.state = .version
                return message
            }
        case .version, .keyExchange, .keyExchangeInit, .newKeys:
            throw SSHKeyExchangeError.inconsistentState
        }
    }

    private func validateVersion(_ version: String) throws {
        guard version.count > 7, version.hasPrefix("SSH-") else {
            throw SSHKeyExchangeError.unsupportedVersion
        }
        let start = version.index(version.startIndex, offsetBy: 4)
        let end = version.index(start, offsetBy: 3)
        guard version[start..<end] == "2.0" else {
            throw SSHKeyExchangeError.unsupportedVersion
        }
    }

    private func createKeyExchangeMessage() -> SSHMessage {
        var cookie = allocator.buffer(capacity: 16)
        cookie.writeBytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        // TODO: "ecdsa-sha2-nistp256" doesnt work, default to aes256 since keys size and algorithm are hardcoded for now
        return .keyExchange(.init(
            cookie: cookie,
            keyExchangeAlgorithms: ["curve25519-sha256", "curve25519-sha256@libssh.org"],
            serverHostKeyAlgorithms: ["ssh-ed25519"],
            encryptionAlgorithmsClientToServer: ["aes256-gcm@openssh.com"],
            encryptionAlgorithmsServerToClient: ["aes256-gcm@openssh.com"],
            macAlgorithmsClientToServer: ["hmac-sha2-256"],
            macAlgorithmsServerToClient: ["hmac-sha2-256"],
            compressionAlgorithmsClientToServer: ["none"],
            compressionAlgorithmsServerToClient: ["none"],
            languagesClientToServer: [],
            languagesServerToClient: []
        ))
    }

    mutating func handle(version: String) throws -> SSHMessage? {
        switch self.state {
        case .version:
            switch self.role {
            case .client:
                try validateVersion(version)

                self.initialExchangeBytes.writeSSHString(version.utf8)

                let message = createKeyExchangeMessage()

                self.initialExchangeBytes.writeCompositeSSHString { buffer in
                    buffer.writeSSHMessage(message)
                }

                self.state = .keyExchange
                return message
            case .server:
                try validateVersion(version)

                self.initialExchangeBytes.writeSSHString(version.utf8)
                self.initialExchangeBytes.writeSSHString("SSH-2.0-SwiftNIOSSH_1.0".utf8)

                self.state = .keyExchange
                return nil
            }
        case .idle, .keyExchange, .keyExchangeInit, .newKeys:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func handle(keyExchange message: SSHMessage.KeyExchangeMessage) throws -> SSHMessage {
        switch self.state {
        case .keyExchange:
            switch self.role {
            case .client:
                // TODO: this is a dirty hack, we re-serialize received response instead of copying the real bytes...
                self.initialExchangeBytes.writeCompositeSSHString { buffer in
                    buffer.writeSSHMessage(SSHMessage.keyExchange(message))
                }

                // verify algorithms
                let message = SSHMessage.keyExchangeInit(self.exhange.initiateKeyExchangeClientSide(allocator: allocator))

                self.state = .keyExchangeInit

                return message
            case .server:
                self.initialExchangeBytes.writeCompositeSSHString { buffer in
                    buffer.writeSSHMessage(SSHMessage.keyExchange(message))
                }

                let message = createKeyExchangeMessage()

                self.initialExchangeBytes.writeCompositeSSHString { buffer in
                    buffer.writeSSHMessage(message)
                }

                self.state = .keyExchangeInit

                return message
            }
        case .idle, .version, .keyExchangeInit, .newKeys:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func handle(keyExchangeInit message: SSHMessage.KeyExchangeECDHInitMessage) throws -> SSHMessage {
        switch self.state {
        case .keyExchangeInit:
            switch self.role {
            case .client:
                throw SSHKeyExchangeError.unexpectedMessage
            case .server(let key):
                let (result, reply) = try self.exhange.completeKeyExchangeServerSide(
                    clientKeyExchangeMessage: message,
                    serverHostKey: key,
                    initialExchangeBytes: &self.initialExchangeBytes,
                    allocator: self.allocator, expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes)

                let message = SSHMessage.keyExchangeReply(reply)
                self.state = .newKeys(result)

                return message
            }
        case .idle, .version, .keyExchange, .newKeys:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func handle(keyExchangeReply message: SSHMessage.KeyExchangeECDHReplyMessage) throws -> SSHMessage {
        switch self.state {
        case .keyExchangeInit:
            switch self.role {
            case .client:
                let result = try self.exhange.receiveServerKeyExchangePayload(
                    serverKeyExchangeMessage: message,
                    initialExchangeBytes: &self.initialExchangeBytes,
                    allocator: allocator,
                    expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes)

                let message = SSHMessage.newKeys

                self.state = .newKeys(result)

                return message
            case .server:
                throw SSHKeyExchangeError.unexpectedMessage
            }
        case .idle, .version, .keyExchange, .newKeys:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func newKeys() throws -> KeyExchangeResult {
        switch self.state {
        case .newKeys(let result):
            return result
        case .idle, .version, .keyExchange, .keyExchangeInit:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }
}
