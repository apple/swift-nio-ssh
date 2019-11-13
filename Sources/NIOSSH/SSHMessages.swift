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

enum SSHMessage {
    enum ParsingError: Error {
        case unknownType
        case incorrectFormat
    }

    case version(String)
    case disconnect(DisconnectMessage)
    case serviceRequest(ServiceRequestMessage)
    case serviceAccept(ServiceAcceptMessage)
    case keyExchange(KeyExchangeMessage)
    case keyExchangeInit(KeyExchangeECDHInitMessage)
    case keyExchangeReply(KeyExchangeECDHReplyMessage)
    case newKeys
}

extension SSHMessage {
    struct DisconnectMessage {
        static let id: UInt8 = 1

        var reason: UInt32
        var description: ByteBuffer
        var tag: ByteBuffer
    }

    struct ServiceRequestMessage {
        static let id: UInt8 = 5

        var service: ByteBuffer
    }

    struct ServiceAcceptMessage {
        static let id: UInt8 = 6

        var service: ByteBuffer
    }

    struct KeyExchangeMessage {
        static let id: UInt8 = 20

        var cookie: ByteBuffer
        var keyExchangeAlgorithms: [Substring]
        var serverHostKeyAlgorithms: [Substring]
        var encryptionAlgorithmsClientToServer: [Substring]
        var encryptionAlgorithmsServerToClient: [Substring]
        var macAlgorithmsClientToServer: [Substring]
        var macAlgorithmsServerToClient: [Substring]
        var compressionAlgorithmsClientToServer: [Substring]
        var compressionAlgorithmsServerToClient: [Substring]
        var languagesClientToServer: [Substring]
        var languagesServerToClient: [Substring]
    }

    // RFC 5656 § 4
    struct KeyExchangeECDHInitMessage {
        // SSH_MSG_KEX_ECDH_INIT
        static let id: UInt8 = 30

        // Q_C, client's ephemeral public key octet string
        var publicKey: ByteBuffer
    }

    // RFC 5656 § 4
    struct KeyExchangeECDHReplyMessage {
        // SSH_MSG_KEX_ECDH_REPLY
        static let id: UInt8 = 31

        // K_S, server's public host key
        var hostKey: NIOSSHHostPublicKey
        // Q_S, server's ephemeral public key octet string
        var publicKey: ByteBuffer
        // the signature on the exchange hash
        var signature: SSHSignature
    }
}

extension ByteBuffer {
    mutating func readSSHMessage(length: UInt32) throws -> SSHMessage {
        let readerIndex = self.readerIndex
        guard var message = self.readSlice(length: Int(length)) else {
            self.moveReaderIndex(to: readerIndex)
            throw SSHMessage.ParsingError.incorrectFormat
        }

        guard let type = message.readInteger(as: UInt8.self) else {
            throw SSHMessage.ParsingError.incorrectFormat
        }

        switch type {
        case SSHMessage.DisconnectMessage.id:
            guard let message = message.readDisconnectMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .disconnect(message)
        case SSHMessage.ServiceRequestMessage.id:
            guard let message = message.readServiceRequestMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .serviceRequest(message)
        case SSHMessage.ServiceAcceptMessage.id:
            guard let message = message.readServiceAcceptMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .serviceAccept(message)
        case SSHMessage.KeyExchangeMessage.id:
            guard let message = message.readKeyExchangeMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .keyExchange(message)
        case SSHMessage.KeyExchangeECDHInitMessage.id:
            guard let message = message.readKeyExchangeECDHInitMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .keyExchangeInit(message)
        case SSHMessage.KeyExchangeECDHReplyMessage.id:
            guard let message = try message.readKeyExchangeECDHReplyMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .keyExchangeReply(message)
        case 21:
            return .newKeys
        default:
            throw SSHMessage.ParsingError.unknownType
        }
    }

    mutating func readDisconnectMessage() -> SSHMessage.DisconnectMessage? {
        var readerIndex = self.readerIndex
        guard let reason = self.readInteger(as: UInt32.self) else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        readerIndex = self.readerIndex
        guard let description = self.readSSHString() else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        readerIndex = self.readerIndex
        guard let tag = self.readSSHString() else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        return .init(reason: reason, description: description, tag: tag)
    }

    mutating func readServiceRequestMessage() -> SSHMessage.ServiceRequestMessage? {
        let readerIndex = self.readerIndex
        guard let service = self.readSSHString() else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        return .init(service: service)
    }

    mutating func readServiceAcceptMessage() -> SSHMessage.ServiceAcceptMessage? {
        let readerIndex = self.readerIndex
        guard let service = self.readSSHString() else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        return .init(service: service)
    }

    mutating func readKeyExchangeMessage() -> SSHMessage.KeyExchangeMessage? {
        var readerIndex = self.readerIndex
        guard let cookie = self.readSlice(length: 16) else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        readerIndex = self.readerIndex
        guard
            let keyExchangeAlgorithms = self.readAlgorithms(),
            let serverHostKeyAlgorithms = self.readAlgorithms(),
            let encryptionAlgorithmsClientToServer = self.readAlgorithms(),
            let encryptionAlgorithmsServerToClient = self.readAlgorithms(),
            let macAlgorithmsClientToServer = self.readAlgorithms(),
            let macAlgorithmsServerToClient = self.readAlgorithms(),
            let compressionAlgorithmsClientToServer = self.readAlgorithms(),
            let compressionAlgorithmsServerToClient = self.readAlgorithms(),
            let languagesClientToServer = self.readAlgorithms(),
            let languagesServerToClient = self.readAlgorithms()
        else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        // first_kex_packet_follows
        readerIndex = self.readerIndex
        guard self.readInteger(as: UInt8.self) != nil else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        // reserved
        readerIndex = self.readerIndex
        guard self.readInteger(as: UInt32.self) == 0 else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        return .init(cookie: cookie,
                     keyExchangeAlgorithms: keyExchangeAlgorithms,
                     serverHostKeyAlgorithms: serverHostKeyAlgorithms,
                     encryptionAlgorithmsClientToServer: encryptionAlgorithmsClientToServer,
                     encryptionAlgorithmsServerToClient: encryptionAlgorithmsServerToClient,
                     macAlgorithmsClientToServer: macAlgorithmsClientToServer,
                     macAlgorithmsServerToClient: macAlgorithmsServerToClient,
                     compressionAlgorithmsClientToServer: compressionAlgorithmsClientToServer,
                     compressionAlgorithmsServerToClient: compressionAlgorithmsServerToClient,
                     languagesClientToServer: languagesClientToServer,
                     languagesServerToClient: languagesServerToClient
        )
    }

    mutating func readKeyExchangeECDHInitMessage() -> SSHMessage.KeyExchangeECDHInitMessage? {
        let readerIndex = self.readerIndex
        guard let publicKey = self.readSSHString() else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }
        return .init(publicKey: publicKey)
    }

    mutating func readKeyExchangeECDHReplyMessage() throws -> SSHMessage.KeyExchangeECDHReplyMessage? {
        var readerIndex = self.readerIndex
        guard let hostKey = try self.readSSHHostKey() else {
            return nil
        }

        readerIndex = self.readerIndex
        guard let publicKey = self.readSSHString() else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        readerIndex = self.readerIndex
        guard let signature = try self.readSSHSignature() else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }

        return .init(hostKey: hostKey, publicKey: publicKey, signature: signature)
    }

    mutating func readAlgorithms() -> [Substring]? {
        let readerIndex = self.readerIndex
        guard var string = self.readSSHString() else {
            self.moveReaderIndex(to: readerIndex)
            return nil
        }
        // readSSHString guarantees that we will be able to read all string bytes
        return string.readString(length: string.readableBytes)!.split(separator: ",")
    }

    @discardableResult
    mutating func writeSSHMessage(_ message: SSHMessage) -> Int {
        var writtenBytes = 0
        switch message {
        case .version(let version):
            writtenBytes += self.writeString(version)
            writtenBytes += self.writeString("\r\n")
        case .disconnect(let message):
            writtenBytes += self.writeInteger(SSHMessage.DisconnectMessage.id)
            writtenBytes += self.writeDisconnectMessage(message)
        case .serviceRequest(let message):
            writtenBytes += self.writeInteger(SSHMessage.ServiceRequestMessage.id)
            writtenBytes += self.writeServiceRequestMessage(message)
        case .serviceAccept(let message):
            writtenBytes += self.writeInteger(SSHMessage.ServiceAcceptMessage.id)
            writtenBytes += self.writeServiceAcceptMessage(message)
        case .keyExchange(let message):
            writtenBytes += self.writeInteger(SSHMessage.KeyExchangeMessage.id)
            writtenBytes += self.writeKeyExchangeMessage(message)
        case .keyExchangeInit(let message):
            writtenBytes += self.writeInteger(SSHMessage.KeyExchangeECDHInitMessage.id)
            writtenBytes += self.writeKeyExchangeECDHInitMessage(message)
        case .keyExchangeReply(let message):
            writtenBytes += self.writeInteger(SSHMessage.KeyExchangeECDHReplyMessage.id)
            writtenBytes += self.writeKeyExchangeECDHReplyMessage(message)
        case .newKeys:
            writtenBytes += self.writeInteger(21 as UInt8)
        }
        return writtenBytes
    }

    mutating func writeDisconnectMessage(_ message: SSHMessage.DisconnectMessage) -> Int {
        var message = message
        var writtenBytes = 0
        writtenBytes += self.writeInteger(message.reason)
        writtenBytes += self.writeSSHString(&message.description)
        writtenBytes += self.writeSSHString(&message.tag)
        return writtenBytes
    }

    mutating func writeServiceRequestMessage(_ message: SSHMessage.ServiceRequestMessage) -> Int {
        var message = message
        return self.writeSSHString(&message.service)
    }

    mutating func writeServiceAcceptMessage(_ message: SSHMessage.ServiceAcceptMessage) -> Int {
        var message = message
        return self.writeSSHString(&message.service)
    }

    mutating func writeKeyExchangeMessage(_ message: SSHMessage.KeyExchangeMessage) -> Int {
        var message = message
        var writtenBytes = 0
        writtenBytes += self.writeBuffer(&message.cookie)
        writtenBytes += self.writeAlgorithms(message.keyExchangeAlgorithms)
        writtenBytes += self.writeAlgorithms(message.serverHostKeyAlgorithms)
        writtenBytes += self.writeAlgorithms(message.encryptionAlgorithmsClientToServer)
        writtenBytes += self.writeAlgorithms(message.encryptionAlgorithmsServerToClient)
        writtenBytes += self.writeAlgorithms(message.macAlgorithmsClientToServer)
        writtenBytes += self.writeAlgorithms(message.macAlgorithmsServerToClient)
        writtenBytes += self.writeAlgorithms(message.compressionAlgorithmsClientToServer)
        writtenBytes += self.writeAlgorithms(message.compressionAlgorithmsServerToClient)
        writtenBytes += self.writeAlgorithms(message.languagesClientToServer)
        writtenBytes += self.writeAlgorithms(message.languagesServerToClient)
        // first_kex_packet_follows
        writtenBytes += self.writeInteger(0 as UInt8)
        // reserved
        writtenBytes += self.writeInteger(0 as UInt32)
        return writtenBytes
    }

    mutating func writeKeyExchangeECDHInitMessage(_ message: SSHMessage.KeyExchangeECDHInitMessage) -> Int {
        var message = message
        return self.writeSSHString(&message.publicKey)
    }

    mutating func writeKeyExchangeECDHReplyMessage(_ message: SSHMessage.KeyExchangeECDHReplyMessage) -> Int {
        var message = message
        var writtenBytes = 0
        writtenBytes += self.writeSSHHostKey(message.hostKey)
        writtenBytes += self.writeSSHString(&message.publicKey)
        writtenBytes += self.writeSSHSignature(message.signature)
        return writtenBytes
    }

    mutating func writeAlgorithms(_ algorithms: [Substring]) -> Int {
        return self.writeSSHString(algorithms.joined(separator: ",").utf8)
    }
}
