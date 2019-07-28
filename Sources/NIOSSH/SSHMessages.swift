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

struct DisconnectMessage {
    static let id: UInt8 = 1

    var reason: UInt32
    var description: ByteBuffer
    var tag: ByteBuffer

    init?(bytes: inout ByteBuffer) {
        guard let reason = bytes.readInteger(as: UInt32.self) else {
            return nil
        }
        self.reason = reason

        guard let description = bytes.readSSHString() else {
            return nil
        }
        self.description = description

        guard let tag = bytes.readSSHString() else {
            return nil
        }
        self.tag = tag
    }
}

struct ServiceRequestMessage {
    static let id: UInt8 = 5

    var service: ByteBuffer

    init?(bytes: inout ByteBuffer) {
        guard let service = bytes.readSSHString() else {
            return nil
        }
        self.service = service
    }
}

struct ServiceAcceptMessage {
    static let id: UInt8 = 6

    var service: ByteBuffer

    init?(bytes: inout ByteBuffer) {
        guard let service = bytes.readSSHString() else {
            return nil
        }
        self.service = service
    }
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

    init?(bytes: inout ByteBuffer) {
        guard let cookie = bytes.readSlice(length: 16) else {
            return nil
        }
        self.cookie = cookie

        guard var keyExchangeAlgorithms = bytes.readSSHString() else {
            return nil
        }
        self.keyExchangeAlgorithms = KeyExchangeAlgorithms.resolve(bytes: &keyExchangeAlgorithms)

        guard var serverHostKeyAlgorithms = bytes.readSSHString() else {
            return nil
        }
        self.serverHostKeyAlgorithms = KeyAuthenticationAlgorithms.resolve(bytes: &serverHostKeyAlgorithms)

        guard var encryptionAlgorithmsClientToServer = bytes.readSSHString() else {
            return nil
        }
        self.encryptionAlgorithmsClientToServer = EncryptionAlgorithms.resolve(bytes: &encryptionAlgorithmsClientToServer)

        guard var encryptionAlgorithmsServerToClient = bytes.readSSHString() else {
            return nil
        }
        self.encryptionAlgorithmsServerToClient = EncryptionAlgorithms.resolve(bytes: &encryptionAlgorithmsServerToClient)

        guard var macAlgorithmsClientToServer = bytes.readSSHString() else {
            return nil
        }
        self.macAlgorithmsClientToServer = MACAlgorithms.resolve(bytes: &macAlgorithmsClientToServer)

        guard var macAlgorithmsServerToClient = bytes.readSSHString() else {
            return nil
        }
        self.macAlgorithmsServerToClient = MACAlgorithms.resolve(bytes: &macAlgorithmsServerToClient)

        guard var compressionAlgorithmsClientToServer = bytes.readSSHString() else {
            return nil
        }
        self.compressionAlgorithmsClientToServer = CompressionAlgorithms.resolve(bytes: &compressionAlgorithmsClientToServer)

        guard var compressionAlgorithmsServerToClient = bytes.readSSHString() else {
            return nil
        }
        self.compressionAlgorithmsServerToClient = CompressionAlgorithms.resolve(bytes: &compressionAlgorithmsServerToClient)

        guard var languagesClientToServer = bytes.readSSHString() else {
            return nil
        }
        self.languagesClientToServer = Languages.resolve(bytes: &languagesClientToServer)

        guard var languagesServerToClient = bytes.readSSHString() else {
            return nil
        }
        self.languagesServerToClient = Languages.resolve(bytes: &languagesServerToClient)

        // first_kex_packet_follows
        _ = bytes.readInteger(as: UInt8.self)
        // reserved
        _ = bytes.readInteger(as: UInt32.self)
    }
}

struct KeyExchangeInitMessage {
    static let id: UInt8 = 30

    var QC: ByteBuffer

    init?(bytes: inout ByteBuffer) {
        guard let QC = bytes.readSSHString() else {
            return nil
        }
        self.QC = QC
    }
}

struct KeyExchangeReplyMessage {
    static let id: UInt8 = 31

    var KS: ByteBuffer
    var QS: ByteBuffer
    var signature: ByteBuffer

    init?(bytes: inout ByteBuffer) {
        guard let KS = bytes.readSSHString() else {
            return nil
        }
        self.KS = KS

        guard let QS = bytes.readSSHString() else {
            return nil
        }
        self.QS = QS

        guard let signature = bytes.readSSHString() else {
            return nil
        }
        self.signature = signature
    }
}

enum Message {
    enum ParsingError: Error {
        case unknownType
        case incorrectFormat
    }

    case version(String)
    case disconnect(DisconnectMessage)
    case serviceRequest(ServiceRequestMessage)
    case serviceAccept(ServiceAcceptMessage)
    case keyExchange(KeyExchangeMessage)
    case keyExchangeInit(KeyExchangeInitMessage)
    case keyExchangeReply(KeyExchangeReplyMessage)
    case newKeys

    static func parse(length: UInt32, bytes: inout ByteBuffer) throws -> Message {
        guard let type = bytes.readInteger(as: UInt8.self) else {
            throw ParsingError.incorrectFormat
        }

        switch type {
        case DisconnectMessage.id:
            guard let message = DisconnectMessage(bytes: &bytes) else {
                throw ParsingError.incorrectFormat
            }
            return .disconnect(message)
        case ServiceRequestMessage.id:
            guard let message = ServiceRequestMessage(bytes: &bytes) else {
                throw ParsingError.incorrectFormat
            }
            return .serviceRequest(message)
        case ServiceAcceptMessage.id:
            guard let message = ServiceAcceptMessage(bytes: &bytes) else {
                throw ParsingError.incorrectFormat
            }
            return .serviceAccept(message)
        case KeyExchangeMessage.id:
            guard let message = KeyExchangeMessage(bytes: &bytes) else {
                throw ParsingError.incorrectFormat
            }
            return .keyExchange(message)
        case KeyExchangeInitMessage.id:
            guard let message = KeyExchangeInitMessage(bytes: &bytes) else {
                throw ParsingError.incorrectFormat
            }
            return .keyExchangeInit(message)
        case KeyExchangeReplyMessage.id:
            guard let message = KeyExchangeReplyMessage(bytes: &bytes) else {
                throw ParsingError.incorrectFormat
            }
            return .keyExchangeReply(message)
        default:
            throw ParsingError.unknownType
        }
    }
}
