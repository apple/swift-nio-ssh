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
        case keyExchange
        case keyExchangeInit
        case newKeys(KeyExchangeResult)
    }

    private let allocator: ByteBufferAllocator
    private var exhange: Curve25519KeyExchange
    private var state: State = .idle
    private var initialExchangeBytes: ByteBuffer

    init(allocator: ByteBufferAllocator) {
        self.allocator = allocator
        self.initialExchangeBytes = allocator.buffer(capacity: 1024)
        self.exhange = Curve25519KeyExchange(ourRole: .client, previousSessionIdentifier: nil)

        self.initialExchangeBytes.writeSSHString("SSH-2.0-SwiftNIOSSH_1.0".utf8)
    }

    mutating func handle(version: String) throws -> SSHMessage {
        switch self.state {
        case .idle:
            guard version.count > 7, version.hasPrefix("SSH-") else {
                throw SSHKeyExchangeError.unsupportedVersion
            }
            let start = version.index(version.startIndex, offsetBy: 4)
            let end = version.index(start, offsetBy: 3)
            guard version[start..<end] == "2.0" else {
                throw SSHKeyExchangeError.unsupportedVersion
            }

            self.initialExchangeBytes.writeSSHString(version.utf8)

            var cookie = allocator.buffer(capacity: 16)
            cookie.writeBytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

            // TODO: "ecdsa-sha2-nistp256" doesnt work
            let message = SSHMessage.keyExchange(.init(
                cookie: cookie,
                keyExchangeAlgorithms: ["curve25519-sha256", "curve25519-sha256@libssh.org"],
                serverHostKeyAlgorithms: ["ssh-ed25519", "ecdsa-sha2-nistp256"],
                encryptionAlgorithmsClientToServer: ["aes128-ctr", "aes256-gcm@openssh.com"],
                encryptionAlgorithmsServerToClient: ["aes128-ctr", "aes256-gcm@openssh.com"],
                macAlgorithmsClientToServer: ["hmac-sha2-256"],
                macAlgorithmsServerToClient: ["hmac-sha2-256"],
                compressionAlgorithmsClientToServer: ["none"],
                compressionAlgorithmsServerToClient: ["none"],
                languagesClientToServer: [],
                languagesServerToClient: []
            ))

            // TODO: this should be somwthing like self.initialExchangeBytes.writeSSHString(bytes of message as payload)
            self.initialExchangeBytes.writeCompositeSSHString { buffer in
                buffer.writeSSHMessage(message)
            }

            self.state = .keyExchange
            return message
        case .keyExchange, .keyExchangeInit, .newKeys:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func handle(keyExchange message: SSHMessage.KeyExchangeMessage) throws -> SSHMessage {
        switch self.state {
        case .keyExchange:
            // TODO: this is a dirty hack, we re-serialize received response instead of copying the real bytes...
            self.initialExchangeBytes.writeCompositeSSHString { buffer in
                buffer.writeSSHMessage(SSHMessage.keyExchange(message))
            }

            // verify algorithms
            let message = SSHMessage.keyExchangeInit(self.exhange.initiateKeyExchangeClientSide(allocator: allocator))

            self.state = .keyExchangeInit

            return message
        case .idle, .keyExchangeInit, .newKeys:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func handle(keyExchangeReply message: SSHMessage.KeyExchangeECDHReplyMessage) throws -> SSHMessage {
        switch self.state {
        case .keyExchangeInit:
            let result = try self.exhange.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: message,
                initialExchangeBytes: &self.initialExchangeBytes,
                allocator: allocator,
                expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes)

            let message = SSHMessage.newKeys

            self.state = .newKeys(result)

            return message
        case .idle, .keyExchange, .newKeys:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }

    mutating func newKeys() throws -> KeyExchangeResult {
        switch self.state {
        case .newKeys(let result):
            return result
        case .idle, .keyExchange, .keyExchangeInit:
            throw SSHKeyExchangeError.unexpectedMessage
        }
    }
}
