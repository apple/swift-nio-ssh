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

// MARK: - Types

enum SSHMessage: Equatable {
    enum ParsingError: Error {
        case unknownType(UInt8)
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
    case userAuthRequest(UserAuthRequestMessage)
    case userAuthFailure(UserAuthFailureMessage)
    case userAuthSuccess
    case globalRequest(GlobalRequestMessage)
    case channelOpen(ChannelOpenMessage)
    case channelOpenConfirmation(ChannelOpenConfirmationMessage)
    case channelOpenFailure(ChannelOpenFailureMessage)
    case channelWindowAdjust(ChannelWindowAdjustMessage)
    case channelData(ChannelDataMessage)
    case channelExtendedData(ChannelExtendedDataMessage)
    case channelEOF(ChannelEOFMessage)
    case channelClose(ChannelCloseMessage)
    case channelRequest(ChannelRequestMessage)
    case channelSuccess(ChannelSuccessMessage)
    case channelFailure(ChannelFailureMessage)
}

extension SSHMessage {
    struct DisconnectMessage: Equatable {
        static let id: UInt8 = 1

        var reason: UInt32
        var description: String
        var tag: ByteBuffer
    }

    struct ServiceRequestMessage: Equatable {
        static let id: UInt8 = 5

        var service: String
    }

    struct ServiceAcceptMessage: Equatable {
        static let id: UInt8 = 6

        var service: String
    }

    struct KeyExchangeMessage: Equatable {
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
        var firstKexPacketFollows: Bool
    }

    enum NewKeysMessage {
        static let id: UInt8 = 21
    }

    // RFC 5656 § 4
    struct KeyExchangeECDHInitMessage: Equatable {
        // SSH_MSG_KEX_ECDH_INIT
        static let id: UInt8 = 30

        // Q_C, client's ephemeral public key octet string
        var publicKey: ByteBuffer
    }

    // RFC 5656 § 4
    struct KeyExchangeECDHReplyMessage: Equatable {
        // SSH_MSG_KEX_ECDH_REPLY
        static let id: UInt8 = 31

        // K_S, server's public host key
        var hostKey: NIOSSHHostPublicKey
        // Q_S, server's ephemeral public key octet string
        var publicKey: ByteBuffer
        // the signature on the exchange hash
        var signature: SSHSignature
    }

    struct UserAuthRequestMessage: Equatable {
        // SSH_MSG_USERAUTH_REQUEST
        static let id: UInt8 = 50

        enum Method: Equatable {
            case none
            case password(String)
        }

        var username: String
        var service: String
        var method: Method
    }

    struct UserAuthFailureMessage: Equatable {
        // SSH_MSG_USERAUTH_FAILURE
        static let id: UInt8 = 51

        var authentications: [Substring]
        var partialSuccess: Bool
    }

    enum UserAuthSuccessMessage {
        static let id: UInt8 = 52
    }

    struct GlobalRequestMessage: Equatable {
        // SSH_MSG_GLOBAL_REQUEST
        static let id: UInt8 = 80

        var name: String
        var wantReply: Bool
        var bytes: ByteBuffer?
    }

    struct ChannelOpenMessage: Equatable {
        // SSH_MSG_CHANNEL_OPEN
        static let id: UInt8 = 90

        // https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-11
        enum ChannelType: String {
            case session = "session"
        }

        var type: ChannelType
        var senderChannel: UInt32
        var initialWindowSize: UInt32
        var maximumPacketSize: UInt32
    }

    struct ChannelOpenConfirmationMessage: Equatable {
        // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
        static let id: UInt8 = 91

        var recipientChannel: UInt32
        var senderChannel: UInt32
        var initialWindowSize: UInt32
        var maximumPacketSize: UInt32
    }

    struct ChannelOpenFailureMessage: Equatable {
        // SSH_MSG_CHANNEL_OPEN_FAILURE
        static let id: UInt8 = 92

        var recipientChannel: UInt32
        var reasonCode: UInt32
        var description: String
        var language: String
    }

    struct ChannelWindowAdjustMessage: Equatable {
        // SSH_MSG_CHANNEL_WINDOW_ADJUST
        static let id: UInt8 = 93

        var recipientChannel: UInt32
        var bytesToAdd: UInt32
    }

    struct ChannelDataMessage: Equatable {
        // SSH_MSG_CHANNEL_DATA
        static let id: UInt8 = 94

        var recipientChannel: UInt32
        var data: ByteBuffer
    }

    struct ChannelExtendedDataMessage: Equatable {
        // SSH_MSG_CHANNEL_EXTENDED_DATA
        static let id: UInt8 = 95

        enum Code: UInt32 {
            case stderr = 1
        }

        var recipientChannel: UInt32
        var dataTypeCode: Code
        var data: ByteBuffer
    }

    struct ChannelEOFMessage: Equatable {
        // SSH_MSG_CHANNEL_EOF
        static let id: UInt8 = 96

        var recipientChannel: UInt32
    }

    struct ChannelCloseMessage: Equatable {
        // SSH_MSG_CHANNEL_CLOSE
        static let id: UInt8 = 97

        var recipientChannel: UInt32
    }

    struct ChannelRequestMessage: Equatable {
        // SSH_MSG_CHANNEL_REQUEST
        static let id: UInt8 = 98

        enum RequestType: Equatable {
            case env(String, String)
            case exec(String)
            case exit(UInt32)
            case unknown
        }

        var recipientChannel: UInt32
        var type: RequestType
        var wantReply: Bool
    }

    struct ChannelSuccessMessage: Equatable {
        // SSH_MSG_CHANNEL_SUCCESS
        static let id: UInt8 = 99

        var recipientChannel: UInt32
    }

    struct ChannelFailureMessage: Equatable {
        // SSH_MSG_CHANNEL_FAILURE
        static let id: UInt8 = 100

        var recipientChannel: UInt32
    }
}

// MARK: - Read Methods

extension ByteBuffer {
    /// Read an SSHMessage from a ByteBuffer.
    ///
    /// This function will consume as many bytes as the message should require. If it cannot read enough bytes,
    /// it will return nil.
    mutating func readSSHMessage() throws -> SSHMessage? {
        return try self.rewindOnNilOrError { `self` in
            guard let type = self.readInteger(as: UInt8.self) else {
                return nil
            }

            switch type {
            case SSHMessage.DisconnectMessage.id:
                guard let message = self.readDisconnectMessage() else {
                    return nil
                }
                return .disconnect(message)
            case SSHMessage.ServiceRequestMessage.id:
                guard let message = self.readServiceRequestMessage() else {
                    return nil
                }
                return .serviceRequest(message)
            case SSHMessage.ServiceAcceptMessage.id:
                guard let message = self.readServiceAcceptMessage() else {
                    return nil
                }
                return .serviceAccept(message)
            case SSHMessage.KeyExchangeMessage.id:
                guard let message = self.readKeyExchangeMessage() else {
                    return nil
                }
                return .keyExchange(message)
            case SSHMessage.KeyExchangeECDHInitMessage.id:
                guard let message = self.readKeyExchangeECDHInitMessage() else {
                    return nil
                }
                return .keyExchangeInit(message)
            case SSHMessage.KeyExchangeECDHReplyMessage.id:
                guard let message = try self.readKeyExchangeECDHReplyMessage() else {
                    return nil
                }
                return .keyExchangeReply(message)
            case SSHMessage.NewKeysMessage.id:
                return .newKeys
            case SSHMessage.UserAuthRequestMessage.id:
                guard let message = self.readUserAuthRequestMessage() else {
                    return nil
                }
                return .userAuthRequest(message)
            case SSHMessage.UserAuthFailureMessage.id:
                guard let message = self.readUserAuthFailureMessage() else {
                    return nil
                }
                return .userAuthFailure(message)
            case SSHMessage.UserAuthSuccessMessage.id:
                return .userAuthSuccess
            case SSHMessage.GlobalRequestMessage.id:
                guard let message = self.readGlobalRequestMessage() else {
                    return nil
                }
                return .globalRequest(message)
            case SSHMessage.ChannelOpenMessage.id:
                guard let message = self.readChannelOpenMessage() else {
                    return nil
                }
                return .channelOpen(message)
            case SSHMessage.ChannelOpenConfirmationMessage.id:
                guard let message = self.readChannelOpenConfirmationMessage() else {
                    return nil
                }
                return .channelOpenConfirmation(message)
            case SSHMessage.ChannelOpenFailureMessage.id:
                guard let message = self.readChannelOpenFailureMessage() else {
                    return nil
                }
                return .channelOpenFailure(message)
            case SSHMessage.ChannelWindowAdjustMessage.id:
                guard let message = self.readChannelWindowAdjustMessage() else {
                    return nil
                }
                return .channelWindowAdjust(message)
            case SSHMessage.ChannelDataMessage.id:
                guard let message = self.readChannelDataMessage() else {
                    return nil
                }
                return .channelData(message)
            case SSHMessage.ChannelExtendedDataMessage.id:
                guard let message = self.readChannelExtendedDataMessage() else {
                    return nil
                }
                return .channelExtendedData(message)
            case SSHMessage.ChannelEOFMessage.id:
                guard let message = self.readChannelEOFMessage() else {
                    return nil
                }
                return .channelEOF(message)
            case SSHMessage.ChannelCloseMessage.id:
                guard let message = self.readChannelCloseMessage() else {
                    return nil
                }
                return .channelClose(message)
            case SSHMessage.ChannelRequestMessage.id:
                guard let message = self.readChannelRequestMessage() else {
                    return nil
                }
                return .channelRequest(message)
            case SSHMessage.ChannelSuccessMessage.id:
                guard let message = self.readChannelSuccessMessage() else {
                    return nil
                }
                return .channelSuccess(message)
            case SSHMessage.ChannelFailureMessage.id:
                guard let message = self.readChannelFailureMessage() else {
                    return nil
                }
                return .channelFailure(message)
            default:
                throw SSHMessage.ParsingError.unknownType(type)
            }
        }
    }

    mutating func readDisconnectMessage() -> SSHMessage.DisconnectMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let reason = self.readInteger(as: UInt32.self),
                let description = self.readSSHStringAsString(),
                let tag = self.readSSHString()
            else {
                return nil
            }

            return SSHMessage.DisconnectMessage(reason: reason, description: description, tag: tag)
        }
    }

    mutating func readServiceRequestMessage() -> SSHMessage.ServiceRequestMessage? {
        return self.rewindReaderOnNil { `self` in
            guard let service = self.readSSHStringAsString() else {
                return nil
            }
            return SSHMessage.ServiceRequestMessage(service: service)
        }
    }

    mutating func readServiceAcceptMessage() -> SSHMessage.ServiceAcceptMessage? {
        return self.rewindReaderOnNil { `self` in
            guard let service = self.readSSHStringAsString() else {
                return nil
            }
            return SSHMessage.ServiceAcceptMessage(service: service)
        }
    }

    mutating func readKeyExchangeMessage() -> SSHMessage.KeyExchangeMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let cookie = self.readSlice(length: 16),
                let keyExchangeAlgorithms = self.readAlgorithms(),
                let serverHostKeyAlgorithms = self.readAlgorithms(),
                let encryptionAlgorithmsClientToServer = self.readAlgorithms(),
                let encryptionAlgorithmsServerToClient = self.readAlgorithms(),
                let macAlgorithmsClientToServer = self.readAlgorithms(),
                let macAlgorithmsServerToClient = self.readAlgorithms(),
                let compressionAlgorithmsClientToServer = self.readAlgorithms(),
                let compressionAlgorithmsServerToClient = self.readAlgorithms(),
                let languagesClientToServer = self.readAlgorithms(),
                let languagesServerToClient = self.readAlgorithms(),
                let firstKexPacketFollows = self.readSSHBoolean()
            else {
                return nil
            }

            // reserved
            guard self.readInteger(as: UInt32.self) == 0 else {
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
                         languagesServerToClient: languagesServerToClient,
                         firstKexPacketFollows: firstKexPacketFollows
            )
        }
    }

    mutating func readKeyExchangeECDHInitMessage() -> SSHMessage.KeyExchangeECDHInitMessage? {
        return self.rewindReaderOnNil { `self` in
            guard let publicKey = self.readSSHString() else {
                return nil
            }
            return SSHMessage.KeyExchangeECDHInitMessage(publicKey: publicKey)
        }
    }

    mutating func readKeyExchangeECDHReplyMessage() throws -> SSHMessage.KeyExchangeECDHReplyMessage? {
        return try self.rewindOnNilOrError { `self` in
            guard
                var hostKeyBytes = self.readSSHString(),
                let hostKey = try hostKeyBytes.readSSHHostKey(),
                let publicKey = self.readSSHString(),
                var signatureBytes = self.readSSHString(),
                let signature = try signatureBytes.readSSHSignature()
            else {
                return nil
            }

            return SSHMessage.KeyExchangeECDHReplyMessage(hostKey: hostKey, publicKey: publicKey, signature: signature)
        }
    }

    mutating func readAlgorithms() -> [Substring]? {
        return self.rewindReaderOnNil { `self` in
            guard let string = self.readSSHStringAsString() else {
                return nil
            }
            return string.split(separator: ",")
        }
    }

    mutating func readUserAuthRequestMessage() -> SSHMessage.UserAuthRequestMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let username = self.readSSHStringAsString(),
                let service = self.readSSHStringAsString(),
                let methodRawValue = self.readSSHStringAsString()
            else {
                return nil
            }

            let method: SSHMessage.UserAuthRequestMessage.Method
            switch methodRawValue {
            case "none":
                method = .none
            case "password":
                guard
                    self.readSSHBoolean() == false,
                    let password = self.readSSHStringAsString()
                else {
                    return nil
                }

                method = .password(password)
            default:
                return nil
            }

            return SSHMessage.UserAuthRequestMessage(username: username, service: service, method: method)
        }
    }

    mutating func readUserAuthFailureMessage() -> SSHMessage.UserAuthFailureMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let authentications = self.readAlgorithms(),
                let partialSuccess = self.readSSHBoolean()
            else {
                return nil
            }

            return SSHMessage.UserAuthFailureMessage(authentications: authentications, partialSuccess: partialSuccess)
        }
    }

    mutating func readGlobalRequestMessage() -> SSHMessage.GlobalRequestMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let name = self.readSSHStringAsString(),
                let wantReply = self.readSSHBoolean()
            else {
                return nil
            }

            let bytes: ByteBuffer?
            if self.readableBytes > 0 {
                bytes = self.readSlice(length: self.readableBytes)
            } else {
                bytes = nil
            }

            return SSHMessage.GlobalRequestMessage(name: name, wantReply: wantReply, bytes: bytes)
        }
    }

    mutating func readChannelOpenMessage() -> SSHMessage.ChannelOpenMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let typeRawValue = self.readSSHStringAsString(),
                let type = SSHMessage.ChannelOpenMessage.ChannelType(rawValue: typeRawValue),
                let senderChannel: UInt32 = self.readInteger(),
                let initialWindowSize: UInt32 = self.readInteger(),
                let maximumPacketSize: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelOpenMessage(type: type, senderChannel: senderChannel, initialWindowSize: initialWindowSize, maximumPacketSize: maximumPacketSize)
        }
    }

    mutating func readChannelOpenConfirmationMessage() -> SSHMessage.ChannelOpenConfirmationMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger(),
                let senderChannel: UInt32 = self.readInteger(),
                let initialWindowSize: UInt32 = self.readInteger(),
                let maximumPacketSize: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelOpenConfirmationMessage(recipientChannel: recipientChannel, senderChannel: senderChannel, initialWindowSize: initialWindowSize, maximumPacketSize: maximumPacketSize)
        }
    }

    mutating func readChannelOpenFailureMessage() -> SSHMessage.ChannelOpenFailureMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger(),
                let reasonCode: UInt32 = self.readInteger(),
                let description = self.readSSHStringAsString(),
                let language = self.readSSHStringAsString()
            else {
                return nil
            }

            return SSHMessage.ChannelOpenFailureMessage(recipientChannel: recipientChannel, reasonCode: reasonCode, description: description, language: language)
        }
    }

    mutating func readChannelWindowAdjustMessage() -> SSHMessage.ChannelWindowAdjustMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger(),
                let bytesToAdd: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelWindowAdjustMessage(recipientChannel: recipientChannel, bytesToAdd: bytesToAdd)
        }
    }

    mutating func readChannelDataMessage() -> SSHMessage.ChannelDataMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger(),
                let data = self.readSSHString()
            else {
                return nil
            }

            return SSHMessage.ChannelDataMessage(recipientChannel: recipientChannel, data: data)
        }
    }

    mutating func readChannelExtendedDataMessage() -> SSHMessage.ChannelExtendedDataMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger(),
                let codeRawValue: UInt32 = self.readInteger(),
                let code = SSHMessage.ChannelExtendedDataMessage.Code(rawValue: codeRawValue),
                let data = self.readSSHString()
            else {
                return nil
            }

            return SSHMessage.ChannelExtendedDataMessage(recipientChannel: recipientChannel, dataTypeCode: code, data: data)
        }
    }

    mutating func readChannelEOFMessage() -> SSHMessage.ChannelEOFMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelEOFMessage(recipientChannel: recipientChannel)
        }
    }

    mutating func readChannelCloseMessage() -> SSHMessage.ChannelCloseMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelCloseMessage(recipientChannel: recipientChannel)
        }
    }

    mutating func readChannelRequestMessage() -> SSHMessage.ChannelRequestMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger(),
                let typeRawValue = self.readSSHStringAsString()
            else {
                return nil
            }

            guard let wantReply = self.readSSHBoolean() else {
                return nil
            }

            let type: SSHMessage.ChannelRequestMessage.RequestType
            switch typeRawValue {
            case "exec":
                guard let command = self.readSSHStringAsString() else {
                    return nil
                }
                type = .exec(command)
            case "exit-status":
                guard let status: UInt32 = self.readInteger() else {
                    return nil
                }
                type = .exit(status)
            case "env":
                guard
                    let name = self.readSSHStringAsString(),
                    let value = self.readSSHStringAsString()
                else {
                    return nil
                }

                type = .env(name, value)
            default:
                type = .unknown
            }

            return SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel, type: type, wantReply: wantReply)
        }
    }

    mutating func readChannelSuccessMessage() -> SSHMessage.ChannelSuccessMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelSuccessMessage(recipientChannel: recipientChannel)
        }
    }

    mutating func readChannelFailureMessage() -> SSHMessage.ChannelFailureMessage? {
        return self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelFailureMessage(recipientChannel: recipientChannel)
        }
    }

    private mutating func readSSHStringAsString() -> String? {
        return self.rewindReaderOnNil { `self` in
            guard var bytes = self.readSSHString() else {
                return nil
            }
            return bytes.readString(length: bytes.readableBytes)
        }
    }
}

// MARK: - Write Methods

extension ByteBuffer {
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
        case .userAuthRequest(let message):
            writtenBytes += self.writeInteger(SSHMessage.UserAuthRequestMessage.id)
            writtenBytes += self.writeUserAuthRequestMessage(message)
        case .userAuthFailure(let message):
            writtenBytes += self.writeInteger(SSHMessage.UserAuthFailureMessage.id)
            writtenBytes += self.writeUserAuthFailureMessage(message)
        case .userAuthSuccess:
            writtenBytes += self.writeInteger(52 as UInt8)
        case .globalRequest(let message):
            writtenBytes += self.writeInteger(SSHMessage.GlobalRequestMessage.id)
            writtenBytes += self.writeGlobalRequestMessage(message)
        case .channelOpen(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelOpenMessage.id)
            writtenBytes += self.writeChannelOpenMessage(message)
        case .channelOpenConfirmation(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelOpenConfirmationMessage.id)
            writtenBytes += self.writeChannelOpenConfirmationMessage(message)
        case .channelOpenFailure(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelOpenFailureMessage.id)
            writtenBytes += self.writeChannelOpenFailureMessage(message)
        case .channelWindowAdjust(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelWindowAdjustMessage.id)
            writtenBytes += self.writeChannelWindowAdjustMessage(message)
        case .channelData(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelDataMessage.id)
            writtenBytes += self.writeChannelDataMessage(message)
        case .channelExtendedData(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelExtendedDataMessage.id)
            writtenBytes += self.writeChannelExtendedDataMessage(message)
        case .channelEOF(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelEOFMessage.id)
            writtenBytes += self.writeChannelEOFMessage(message)
        case .channelClose(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelCloseMessage.id)
            writtenBytes += self.writeChannelCloseMessage(message)
        case .channelRequest(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelRequestMessage.id)
            writtenBytes += self.writeChannelRequestMessage(message)
        case .channelSuccess(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelSuccessMessage.id)
            writtenBytes += self.writeChannelSuccessMessage(message)
        case .channelFailure(let message):
            writtenBytes += self.writeInteger(SSHMessage.ChannelFailureMessage.id)
            writtenBytes += self.writeChannelFailureMessage(message)
        }
        return writtenBytes
    }

    mutating func writeDisconnectMessage(_ message: SSHMessage.DisconnectMessage) -> Int {
        var message = message
        var writtenBytes = 0
        writtenBytes += self.writeInteger(message.reason)
        writtenBytes += self.writeSSHString(message.description.utf8)
        writtenBytes += self.writeSSHString(&message.tag)
        return writtenBytes
    }

    mutating func writeServiceRequestMessage(_ message: SSHMessage.ServiceRequestMessage) -> Int {
        return self.writeSSHString(message.service.utf8)
    }

    mutating func writeServiceAcceptMessage(_ message: SSHMessage.ServiceAcceptMessage) -> Int {
        return self.writeSSHString(message.service.utf8)
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
        writtenBytes += self.writeSSHBoolean(message.firstKexPacketFollows)
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
        writtenBytes += self.writeCompositeSSHString { buffer in
            buffer.writeSSHHostKey(message.hostKey)
        }
        writtenBytes += self.writeSSHString(&message.publicKey)
        writtenBytes += self.writeCompositeSSHString { buffer in
            buffer.writeSSHSignature(message.signature)
        }
        return writtenBytes
    }

    mutating func writeAlgorithms(_ algorithms: [Substring]) -> Int {
        return self.writeSSHString(algorithms.joined(separator: ",").utf8)
    }

    mutating func writeUserAuthRequestMessage(_ message: SSHMessage.UserAuthRequestMessage) -> Int {
        var writtenBytes = 0
        writtenBytes += self.writeSSHString(message.username.utf8)
        writtenBytes += self.writeSSHString(message.service.utf8)

        switch message.method {
        case .none:
            writtenBytes += self.writeSSHString("none".utf8)
        case .password(let password):
            writtenBytes += self.writeSSHString("password".utf8)
            writtenBytes += self.writeSSHBoolean(false)
            writtenBytes += self.writeSSHString(password.utf8)
        }

        return writtenBytes
    }

    mutating func writeUserAuthFailureMessage(_ message: SSHMessage.UserAuthFailureMessage) -> Int {
        var writtenBytes = 0
        writtenBytes += self.writeAlgorithms(message.authentications)
        writtenBytes += self.writeSSHBoolean(message.partialSuccess)
        return writtenBytes
    }

    mutating func writeGlobalRequestMessage(_ message: SSHMessage.GlobalRequestMessage) -> Int {
        var writtenBytes = 0

        writtenBytes += self.writeSSHString(message.name.utf8)
        writtenBytes += self.writeSSHBoolean(message.wantReply)

        return writtenBytes
    }

    mutating func writeChannelOpenMessage(_ message: SSHMessage.ChannelOpenMessage) -> Int {
        var writtenBytes = 0

        switch message.type {
        case .session:
            writtenBytes += self.writeSSHString("session".utf8)
        }

        writtenBytes += self.writeInteger(message.senderChannel)
        writtenBytes += self.writeInteger(message.initialWindowSize)
        writtenBytes += self.writeInteger(message.maximumPacketSize)

        return writtenBytes
    }

    mutating func writeChannelOpenConfirmationMessage(_ message: SSHMessage.ChannelOpenConfirmationMessage) -> Int {
        var writtenBytes = 0

        writtenBytes += self.writeInteger(message.recipientChannel)
        writtenBytes += self.writeInteger(message.senderChannel)
        writtenBytes += self.writeInteger(message.initialWindowSize)
        writtenBytes += self.writeInteger(message.maximumPacketSize)

        return writtenBytes
    }

    mutating func writeChannelOpenFailureMessage(_ message: SSHMessage.ChannelOpenFailureMessage) -> Int {
        var writtenBytes = 0

        writtenBytes += self.writeInteger(message.recipientChannel)
        writtenBytes += self.writeInteger(message.reasonCode)
        writtenBytes += self.writeSSHString(message.description.utf8)
        writtenBytes += self.writeSSHString(message.language.utf8)

        return writtenBytes
    }

    mutating func writeChannelWindowAdjustMessage(_ message: SSHMessage.ChannelWindowAdjustMessage) -> Int {
        var writtenBytes = 0

        writtenBytes += self.writeInteger(message.recipientChannel)
        writtenBytes += self.writeInteger(message.bytesToAdd)

        return writtenBytes
    }

    mutating func writeChannelDataMessage(_ message: SSHMessage.ChannelDataMessage) -> Int {
        var message = message
        var writtenBytes = 0

        writtenBytes += self.writeInteger(message.recipientChannel)
        writtenBytes += self.writeSSHString(&message.data)

        return writtenBytes
    }

    mutating func writeChannelExtendedDataMessage(_ message: SSHMessage.ChannelExtendedDataMessage) -> Int {
        var message = message
        var writtenBytes = 0

        writtenBytes += self.writeInteger(message.recipientChannel)
        writtenBytes += self.writeInteger(message.dataTypeCode.rawValue)
        writtenBytes += self.writeSSHString(&message.data)

        return writtenBytes
    }

    mutating func writeChannelEOFMessage(_ message: SSHMessage.ChannelEOFMessage) -> Int {
        var writtenBytes = 0
        writtenBytes += self.writeInteger(message.recipientChannel)
        return writtenBytes
    }

    mutating func writeChannelCloseMessage(_ message: SSHMessage.ChannelCloseMessage) -> Int {
        var writtenBytes = 0
        writtenBytes += self.writeInteger(message.recipientChannel)
        return writtenBytes
    }

    mutating func writeChannelRequestMessage(_ message: SSHMessage.ChannelRequestMessage) -> Int {
        var writtenBytes = 0

        writtenBytes += self.writeInteger(message.recipientChannel)
        switch message.type {
        case .env:
            writtenBytes += self.writeSSHString("env".utf8)
        case .exec:
            writtenBytes += self.writeSSHString("exec".utf8)
        case .exit:
            writtenBytes += self.writeSSHString("exit-status".utf8)
        case .unknown:
            preconditionFailure()
        }

        writtenBytes += self.writeSSHBoolean(message.wantReply)

        switch message.type {
        case .env(let name, let value):
            writtenBytes += self.writeSSHString(name.utf8)
            writtenBytes += self.writeSSHString(value.utf8)
        case .exec(let command):
            writtenBytes += self.writeSSHString(command.utf8)
        case .exit(let status):
            writtenBytes += self.writeInteger(status)
        case .unknown:
            preconditionFailure()
        }

        return writtenBytes
    }

    mutating func writeChannelSuccessMessage(_ message: SSHMessage.ChannelSuccessMessage) -> Int {
        var writtenBytes = 0
        writtenBytes += self.writeInteger(message.recipientChannel)
        return writtenBytes
    }

    mutating func writeChannelFailureMessage(_ message: SSHMessage.ChannelFailureMessage) -> Int {
        var writtenBytes = 0
        writtenBytes += self.writeInteger(message.recipientChannel)
        return writtenBytes
    }
}
