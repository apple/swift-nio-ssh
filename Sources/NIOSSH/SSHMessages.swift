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
        var keyExchangeAlgorithms: KeyExchangeAlgorithms
        var serverHostKeyAlgorithms: KeyAuthenticationAlgorithms
        var encryptionAlgorithmsClientToServer: EncryptionAlgorithms
        var encryptionAlgorithmsServerToClient: EncryptionAlgorithms
        var macAlgorithmsClientToServer: MACAlgorithms
        var macAlgorithmsServerToClient: MACAlgorithms
        var compressionAlgorithmsClientToServer: CompressionAlgorithms
        var compressionAlgorithmsServerToClient: CompressionAlgorithms
        var languagesClientToServer: Languages
        var languagesServerToClient: Languages
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
        var hostKey: ByteBuffer
        // Q_S, server's ephemeral public key octet string
        var publicKey: ByteBuffer
        // the signature on the exchange hash
        var signature: ByteBuffer
    }
}

extension ByteBuffer {
    mutating func readSSHMessage(length: UInt32) throws -> SSHMessage {
        guard let type = self.readInteger(as: UInt8.self) else {
            throw SSHMessage.ParsingError.incorrectFormat
        }

        switch type {
        case SSHMessage.DisconnectMessage.id:
            guard let message = self.readDisconnectMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .disconnect(message)
        case SSHMessage.ServiceRequestMessage.id:
            guard let message = self.readServiceRequestMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .serviceRequest(message)
        case SSHMessage.ServiceAcceptMessage.id:
            guard let message = self.readServiceAcceptMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .serviceAccept(message)
        case SSHMessage.KeyExchangeMessage.id:
            guard let message = self.readKeyExchangeMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .keyExchange(message)
        case SSHMessage.KeyExchangeECDHInitMessage.id:
            guard let message = self.readKeyExchangeECDHInitMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .keyExchangeInit(message)
        case SSHMessage.KeyExchangeECDHReplyMessage.id:
            guard let message = self.readKeyExchangeECDHReplyMessage() else {
                throw SSHMessage.ParsingError.incorrectFormat
            }
            return .keyExchangeReply(message)
        default:
            throw SSHMessage.ParsingError.unknownType
        }
    }

    mutating func readDisconnectMessage() -> SSHMessage.DisconnectMessage? {
        guard let reason = self.readInteger(as: UInt32.self) else {
            return nil
        }

        guard let description = self.readSSHString() else {
            return nil
        }

        guard let tag = self.readSSHString() else {
            return nil
        }

        return .init(reason: reason, description: description, tag: tag)
    }

    mutating func readServiceRequestMessage() -> SSHMessage.ServiceRequestMessage? {
        guard let service = self.readSSHString() else {
            return nil
        }

        return .init(service: service)
    }

    mutating func readServiceAcceptMessage() -> SSHMessage.ServiceAcceptMessage? {
        guard let service = self.readSSHString() else {
            return nil
        }

        return .init(service: service)
    }

    mutating func readKeyExchangeMessage() -> SSHMessage.KeyExchangeMessage? {
        guard let cookie = self.readSlice(length: 16) else {
            return nil
        }

        guard let keyExchangeAlgorithms = self.readKeyExchangeAlgorithms() else {
            return nil
        }

        guard let serverHostKeyAlgorithms = self.readKeyAuthenticationAlgorithms() else {
            return nil
        }

        guard let encryptionAlgorithmsClientToServer = self.readEncryptionAlgorithms() else {
            return nil
        }

        guard let encryptionAlgorithmsServerToClient = self.readEncryptionAlgorithms() else {
            return nil
        }

        guard let macAlgorithmsClientToServer = self.readMACAlgorithms() else {
            return nil
        }

        guard let macAlgorithmsServerToClient = self.readMACAlgorithms() else {
            return nil
        }

        guard let compressionAlgorithmsClientToServer = self.readCompressionAlgorithms() else {
            return nil
        }

        guard let compressionAlgorithmsServerToClient = self.readCompressionAlgorithms() else {
            return nil
        }

        guard let languagesClientToServer = self.readLanguages() else {
            return nil
        }

        guard let languagesServerToClient = self.readLanguages() else {
            return nil
        }

        // first_kex_packet_follows
        _ = self.readInteger(as: UInt8.self)
        // reserved
        _ = self.readInteger(as: UInt32.self)

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
        guard let publicKey = self.readSSHString() else {
            return nil
        }
        return .init(publicKey: publicKey)
    }

    mutating func readKeyExchangeECDHReplyMessage() -> SSHMessage.KeyExchangeECDHReplyMessage? {
        guard let hostKey = self.readSSHString() else {
            return nil
        }

        guard let publicKey = self.readSSHString() else {
            return nil
        }

        guard let signature = self.readSSHString() else {
            return nil
        }

        return .init(hostKey: hostKey, publicKey: publicKey, signature: signature)
    }
}
