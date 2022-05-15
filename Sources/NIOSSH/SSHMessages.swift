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

import NIOCore

// MARK: - Types

enum SSHMessage: Equatable {
    enum ParsingError: Error {
        case unknownType(UInt8)
        case incorrectFormat
    }

    case version(String)
    case disconnect(DisconnectMessage)
    case ignore(IgnoreMessage)
    case unimplemented(UnimplementedMessage)
    case debug(DebugMessage)
    case serviceRequest(ServiceRequestMessage)
    case serviceAccept(ServiceAcceptMessage)
    case keyExchange(KeyExchangeMessage)
    case keyExchangeInit(KeyExchangeECDHInitMessage)
    case keyExchangeReply(KeyExchangeECDHReplyMessage)
    case newKeys
    case userAuthRequest(UserAuthRequestMessage)
    case userAuthFailure(UserAuthFailureMessage)
    case userAuthSuccess
    case userAuthBanner(UserAuthBannerMessage)
    case userAuthPKOK(UserAuthPKOKMessage)
    case globalRequest(GlobalRequestMessage)
    case requestSuccess(RequestSuccessMessage)
    case requestFailure
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
        var tag: String
    }

    struct IgnoreMessage: Equatable {
        static let id: UInt8 = 2

        var data: ByteBuffer
    }

    struct UnimplementedMessage: Equatable {
        static let id: UInt8 = 3

        var sequenceNumber: UInt32
    }

    struct DebugMessage: Equatable {
        static let id: UInt8 = 4

        var alwaysDisplay: Bool
        var message: String
        var language: String
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
        var hostKey: NIOSSHPublicKey
        // Q_S, server's ephemeral public key octet string
        var publicKey: ByteBuffer
        // the signature on the exchange hash
        var signature: NIOSSHSignature
    }

    struct UserAuthRequestMessage: Equatable {
        // SSH_MSG_USERAUTH_REQUEST
        static let id: UInt8 = 50

        enum Method: Equatable {
            case none
            case publicKey(PublicKeyAuthType)
            case password(String)
        }

        enum PublicKeyAuthType: Equatable {
            case known(key: NIOSSHPublicKey, signature: NIOSSHSignature?)
            case unknown
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

    struct UserAuthBannerMessage: Equatable {
        // SSH_MSG_USERAUTH_BANNER
        static let id: UInt8 = 53

        /// message to display to user in client, encoded as ISO-10646 UTF-8 following RFC 3629
        var message: String

        /// tag identifying language of banner, following RFC 3066
        var languageTag: String
    }

    struct UserAuthPKOKMessage: Equatable {
        // SSH_MSG_USERAUTH_PK_OK
        static let id: UInt8 = 60

        var key: NIOSSHPublicKey
    }

    struct GlobalRequestMessage: Equatable {
        // SSH_MSG_GLOBAL_REQUEST
        static let id: UInt8 = 80

        enum RequestType: Equatable {
            case tcpipForward(String, UInt32)
            case cancelTcpipForward(String, UInt32)
            case unknown(String, ByteBuffer)
        }

        var wantReply: Bool
        var type: RequestType
    }

    struct RequestSuccessMessage: Equatable {
        static let id: UInt8 = 81

        var buffer: ByteBuffer
    }

    enum RequestFailureMessage {
        static let id: UInt8 = 82
    }

    struct ChannelOpenMessage: Equatable {
        // SSH_MSG_CHANNEL_OPEN
        static let id: UInt8 = 90

        // https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-11
        enum ChannelType: Equatable {
            case session
            case forwardedTCPIP(ForwardedTCPIP)
            case directTCPIP(DirectTCPIP)
        }

        struct ForwardedTCPIP: Equatable {
            var hostListening: String
            var portListening: UInt16
            var originatorAddress: SocketAddress
        }

        struct DirectTCPIP: Equatable {
            var hostToConnectTo: String
            var portToConnectTo: UInt16
            var originatorAddress: SocketAddress
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
            case exitStatus(UInt32)
            case exitSignal(String, Bool, String, String)
            case ptyReq(PtyReq)
            case shell
            case subsystem(String)
            case windowChange(WindowChange)
            case xonXoff(Bool)
            case signal(String)
            case unknown
        }

        struct PtyReq: Equatable {
            var termVariable: String
            var characterWidth: UInt32
            var rowHeight: UInt32
            var pixelWidth: UInt32
            var pixelHeight: UInt32
            var terminalModes: SSHTerminalModes
        }

        struct WindowChange: Equatable {
            var characterWidth: UInt32
            var rowHeight: UInt32
            var pixelWidth: UInt32
            var pixelHeight: UInt32
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
        try self.rewindOnNilOrError { `self` in
            guard let type = self.readInteger(as: UInt8.self) else {
                return nil
            }

            switch type {
            case SSHMessage.DisconnectMessage.id:
                guard let message = self.readDisconnectMessage() else {
                    return nil
                }
                return .disconnect(message)
            case SSHMessage.IgnoreMessage.id:
                guard let message = self.readIgnoreMessage() else {
                    return nil
                }
                return .ignore(message)
            case SSHMessage.UnimplementedMessage.id:
                guard let message = self.readUnimplementedMessage() else {
                    return nil
                }
                return .unimplemented(message)
            case SSHMessage.DebugMessage.id:
                guard let message = self.readDebugMessage() else {
                    return nil
                }
                return .debug(message)
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
                guard let message = try self.readUserAuthRequestMessage() else {
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
            case SSHMessage.UserAuthBannerMessage.id:
                guard let message = self.readUserAuthBannerMessage() else {
                    return nil
                }
                return .userAuthBanner(message)
            case SSHMessage.UserAuthPKOKMessage.id:
                guard let message = try self.readUserAuthPKOKMessage() else {
                    return nil
                }
                return .userAuthPKOK(message)
            case SSHMessage.GlobalRequestMessage.id:
                guard let message = try self.readGlobalRequestMessage() else {
                    return nil
                }
                return .globalRequest(message)
            case SSHMessage.RequestSuccessMessage.id:
                guard let message = self.readRequestSuccessMessage() else {
                    return nil
                }
                return .requestSuccess(message)
            case SSHMessage.RequestFailureMessage.id:
                return .requestFailure
            case SSHMessage.ChannelOpenMessage.id:
                guard let message = try self.readChannelOpenMessage() else {
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
                guard let message = try self.readChannelRequestMessage() else {
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
        self.rewindReaderOnNil { `self` in
            guard
                let reason = self.readInteger(as: UInt32.self),
                let description = self.readSSHStringAsString(),
                let tag = self.readSSHStringAsString()
            else {
                return nil
            }

            return SSHMessage.DisconnectMessage(reason: reason, description: description, tag: tag)
        }
    }

    mutating func readIgnoreMessage() -> SSHMessage.IgnoreMessage? {
        self.rewindReaderOnNil { `self` in
            guard let data = self.readSSHString() else {
                return nil
            }

            return SSHMessage.IgnoreMessage(data: data)
        }
    }

    mutating func readUnimplementedMessage() -> SSHMessage.UnimplementedMessage? {
        self.rewindReaderOnNil { `self` in
            guard let sequenceNumber = self.readInteger(as: UInt32.self) else {
                return nil
            }

            return SSHMessage.UnimplementedMessage(sequenceNumber: sequenceNumber)
        }
    }

    mutating func readDebugMessage() -> SSHMessage.DebugMessage? {
        self.rewindReaderOnNil { `self` in
            guard
                let alwaysDisplay = self.readSSHBoolean(),
                let message = self.readSSHStringAsString(),
                let language = self.readSSHStringAsString() else {
                return nil
            }

            return SSHMessage.DebugMessage(alwaysDisplay: alwaysDisplay, message: message, language: language)
        }
    }

    mutating func readServiceRequestMessage() -> SSHMessage.ServiceRequestMessage? {
        self.rewindReaderOnNil { `self` in
            guard let service = self.readSSHStringAsString() else {
                return nil
            }
            return SSHMessage.ServiceRequestMessage(service: service)
        }
    }

    mutating func readServiceAcceptMessage() -> SSHMessage.ServiceAcceptMessage? {
        self.rewindReaderOnNil { `self` in
            guard let service = self.readSSHStringAsString() else {
                return nil
            }
            return SSHMessage.ServiceAcceptMessage(service: service)
        }
    }

    mutating func readKeyExchangeMessage() -> SSHMessage.KeyExchangeMessage? {
        self.rewindReaderOnNil { `self` in
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
                         firstKexPacketFollows: firstKexPacketFollows)
        }
    }

    mutating func readKeyExchangeECDHInitMessage() -> SSHMessage.KeyExchangeECDHInitMessage? {
        self.rewindReaderOnNil { `self` in
            guard let publicKey = self.readSSHString() else {
                return nil
            }
            return SSHMessage.KeyExchangeECDHInitMessage(publicKey: publicKey)
        }
    }

    mutating func readKeyExchangeECDHReplyMessage() throws -> SSHMessage.KeyExchangeECDHReplyMessage? {
        try self.rewindOnNilOrError { `self` in
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
        self.rewindReaderOnNil { `self` in
            guard let string = self.readSSHStringAsString() else {
                return nil
            }
            return string.split(separator: ",")
        }
    }

    mutating func readUserAuthRequestMessage() throws -> SSHMessage.UserAuthRequestMessage? {
        try self.rewindOnNilOrError { `self` in
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
            case "publickey":
                guard
                    let expectSignature = self.readSSHBoolean(),
                    let algorithmName = self.readSSHString(),
                    var keyBytes = self.readSSHString()
                else {
                    return nil
                }

                if NIOSSHPublicKey.knownAlgorithms.contains(where: { $0.elementsEqual(algorithmName.readableBytesView) }) {
                    // This is a known algorithm, we can load the key.
                    guard let publicKey = try keyBytes.readSSHHostKey() else {
                        return nil
                    }

                    guard algorithmName.readableBytesView.elementsEqual(publicKey.keyPrefix) else {
                        throw NIOSSHError.invalidSSHMessage(reason: "algorithm and key mismatch in user auth request")
                    }

                    if expectSignature {
                        guard var signatureBytes = self.readSSHString(), let signature = try signatureBytes.readSSHSignature() else {
                            return nil
                        }

                        method = .publicKey(.known(key: publicKey, signature: signature))
                    } else {
                        method = .publicKey(.known(key: publicKey, signature: nil))
                    }
                } else {
                    // This is not an algorithm we know. Consume the signature if we're expecting it.
                    if expectSignature {
                        guard let _ = self.readSSHString() else {
                            return nil
                        }
                    }

                    method = .publicKey(.unknown)
                }
            default:
                return nil
            }

            return SSHMessage.UserAuthRequestMessage(username: username, service: service, method: method)
        }
    }

    mutating func readUserAuthFailureMessage() -> SSHMessage.UserAuthFailureMessage? {
        self.rewindReaderOnNil { `self` in
            guard
                let authentications = self.readAlgorithms(),
                let partialSuccess = self.readSSHBoolean()
            else {
                return nil
            }

            return SSHMessage.UserAuthFailureMessage(authentications: authentications, partialSuccess: partialSuccess)
        }
    }

    mutating func readUserAuthBannerMessage() -> SSHMessage.UserAuthBannerMessage? {
        self.rewindReaderOnNil { `self` in
            guard let message = self.readSSHStringAsString(),
                let languageTag = self.readSSHStringAsString()
            else {
                return nil
            }

            return SSHMessage.UserAuthBannerMessage(message: message, languageTag: languageTag)
        }
    }

    mutating func readUserAuthPKOKMessage() throws -> SSHMessage.UserAuthPKOKMessage? {
        try self.rewindOnNilOrError { `self` in
            guard
                let publicKeyType = self.readSSHString(),
                var publicKeyBytes = self.readSSHString()
            else {
                return nil
            }

            guard NIOSSHPublicKey.knownAlgorithms.contains(where: { $0.elementsEqual(publicKeyType.readableBytesView) }) else {
                throw NIOSSHError.invalidSSHMessage(reason: "unsupported key type in PK_OK")
            }

            guard let publicKey = try publicKeyBytes.readSSHHostKey() else {
                return nil
            }

            // Validate consistency here.
            guard publicKeyType.readableBytesView.elementsEqual(publicKey.keyPrefix) else {
                throw NIOSSHError.invalidSSHMessage(reason: "inconsistent key type")
            }

            return .init(key: publicKey)
        }
    }

    mutating func readGlobalRequestMessage() throws -> SSHMessage.GlobalRequestMessage? {
        self.rewindReaderOnNil { `self` in
            guard
                let name = self.readSSHStringAsString(),
                let wantReply = self.readSSHBoolean()
            else {
                return nil
            }

            let type: SSHMessage.GlobalRequestMessage.RequestType

            switch name {
            case "tcpip-forward":
                guard
                    let addressToBind = self.readSSHStringAsString(),
                    let port = self.readInteger(as: UInt32.self)
                else {
                    return nil
                }

                type = .tcpipForward(addressToBind, port)

            case "cancel-tcpip-forward":
                guard
                    let addressToBind = self.readSSHStringAsString(),
                    let port = self.readInteger(as: UInt32.self)
                else {
                    return nil
                }

                type = .cancelTcpipForward(addressToBind, port)

            default:
                // The list of global request types can be, and is, extended.
                // Throwing an error would abort the connection, therefore the request is wrapped to be `unknown`.
                //
                // The remainder of the payload is formatted according to the spec associated by the request type.
                // It cannot be parsed unless the request type is a known type.
                // So the remainder of the payload is attached as-is.
                let globalRequestPayload = self.readSlice(length: self.readableBytes)!

                type = .unknown(name, globalRequestPayload)
            }

            return SSHMessage.GlobalRequestMessage(wantReply: wantReply, type: type)
        }
    }

    mutating func readRequestSuccessMessage() -> SSHMessage.RequestSuccessMessage? {
        // This force unwrap cannot fail
        let responseData = self.readSlice(length: self.readableBytes)!
        return SSHMessage.RequestSuccessMessage(buffer: responseData)
    }

    mutating func readChannelOpenMessage() throws -> SSHMessage.ChannelOpenMessage? {
        try self.rewindOnNilOrError { `self` in
            guard
                let typeRawValue = self.readSSHStringAsString(),
                let senderChannel: UInt32 = self.readInteger(),
                let initialWindowSize: UInt32 = self.readInteger(),
                let maximumPacketSize: UInt32 = self.readInteger()
            else {
                return nil
            }

            let type: SSHMessage.ChannelOpenMessage.ChannelType

            switch typeRawValue {
            case "session":
                type = .session

            case "forwarded-tcpip":
                guard
                    let hostListening = self.readSSHStringAsString(),
                    let portListening = self.readInteger(as: UInt32.self),
                    let originatorIP = self.readSSHStringAsString(),
                    let originatorPort = self.readInteger(as: UInt32.self)
                else {
                    return nil
                }

                guard portListening <= UInt16.max, originatorPort <= UInt16.max else {
                    throw NIOSSHError.unknownPacketType(diagnostic: "Invalid port values: \(portListening) \(originatorPort)")
                }

                let originator = try SocketAddress(ipAddress: originatorIP, port: Int(originatorPort))

                type = .forwardedTCPIP(.init(hostListening: hostListening, portListening: UInt16(portListening), originatorAddress: originator))

            case "direct-tcpip":
                guard
                    let hostToConnectTo = self.readSSHStringAsString(),
                    let portToConnectTo = self.readInteger(as: UInt32.self),
                    let originatorIP = self.readSSHStringAsString(),
                    let originatorPort = self.readInteger(as: UInt32.self)
                else {
                    return nil
                }

                guard portToConnectTo <= UInt16.max, originatorPort <= UInt16.max else {
                    throw NIOSSHError.unknownPacketType(diagnostic: "Invalid port values: \(portToConnectTo) \(originatorPort)")
                }

                let originator = try SocketAddress(ipAddress: originatorIP, port: Int(originatorPort))

                type = .directTCPIP(.init(hostToConnectTo: hostToConnectTo, portToConnectTo: UInt16(portToConnectTo), originatorAddress: originator))

            default:
                throw NIOSSHError.unknownPacketType(diagnostic: "Channel request with \(typeRawValue)")
            }

            return SSHMessage.ChannelOpenMessage(type: type, senderChannel: senderChannel, initialWindowSize: initialWindowSize, maximumPacketSize: maximumPacketSize)
        }
    }

    mutating func readChannelOpenConfirmationMessage() -> SSHMessage.ChannelOpenConfirmationMessage? {
        self.rewindReaderOnNil { `self` in
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
        self.rewindReaderOnNil { `self` in
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
        self.rewindReaderOnNil { `self` in
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
        self.rewindReaderOnNil { `self` in
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
        self.rewindReaderOnNil { `self` in
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
        self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelEOFMessage(recipientChannel: recipientChannel)
        }
    }

    mutating func readChannelCloseMessage() -> SSHMessage.ChannelCloseMessage? {
        self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelCloseMessage(recipientChannel: recipientChannel)
        }
    }

    mutating func readChannelRequestMessage() throws -> SSHMessage.ChannelRequestMessage? {
        try self.rewindOnNilOrError { `self` in
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
                type = .exitStatus(status)
            case "env":
                guard
                    let name = self.readSSHStringAsString(),
                    let value = self.readSSHStringAsString()
                else {
                    return nil
                }

                type = .env(name, value)
            case "exit-signal":
                guard
                    let signalName = self.readSSHStringAsString(),
                    let coreDumped = self.readSSHBoolean(),
                    let errorMessage = self.readSSHStringAsString(),
                    let language = self.readSSHStringAsString()
                else {
                    return nil
                }

                type = .exitSignal(signalName, coreDumped, errorMessage, language)
            case "pty-req":
                guard
                    let termVariable = self.readSSHStringAsString(),
                    let termWidth = self.readInteger(as: UInt32.self),
                    let termHeight = self.readInteger(as: UInt32.self),
                    let pixelWidth = self.readInteger(as: UInt32.self),
                    let pixelHeight = self.readInteger(as: UInt32.self),
                    var encodedTerminalModes = self.readSSHString()
                else {
                    return nil
                }

                type = .ptyReq(.init(termVariable: termVariable,
                                     characterWidth: termWidth,
                                     rowHeight: termHeight,
                                     pixelWidth: pixelWidth,
                                     pixelHeight: pixelHeight,
                                     terminalModes: try encodedTerminalModes.readSSHTerminalModes()))
            case "shell":
                type = .shell
            case "subsystem":
                guard let name = self.readSSHStringAsString() else {
                    return nil
                }
                type = .subsystem(name)
            case "window-change":
                guard
                    let termWidth = self.readInteger(as: UInt32.self),
                    let termHeight = self.readInteger(as: UInt32.self),
                    let pixelWidth = self.readInteger(as: UInt32.self),
                    let pixelHeight = self.readInteger(as: UInt32.self)
                else {
                    return nil
                }

                type = .windowChange(.init(characterWidth: termWidth, rowHeight: termHeight, pixelWidth: pixelWidth, pixelHeight: pixelHeight))
            case "xon-xoff":
                guard let clientCanDo = self.readSSHBoolean() else {
                    return nil
                }
                type = .xonXoff(clientCanDo)

            case "signal":
                guard let signalName = self.readSSHStringAsString() else {
                    return nil
                }
                type = .signal(signalName)
            default:
                type = .unknown
            }

            return SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel, type: type, wantReply: wantReply)
        }
    }

    mutating func readChannelSuccessMessage() -> SSHMessage.ChannelSuccessMessage? {
        self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelSuccessMessage(recipientChannel: recipientChannel)
        }
    }

    mutating func readChannelFailureMessage() -> SSHMessage.ChannelFailureMessage? {
        self.rewindReaderOnNil { `self` in
            guard
                let recipientChannel: UInt32 = self.readInteger()
            else {
                return nil
            }

            return SSHMessage.ChannelFailureMessage(recipientChannel: recipientChannel)
        }
    }

    mutating func readSSHStringAsString() -> String? {
        self.rewindReaderOnNil { `self` in
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
        case .ignore(let message):
            writtenBytes += self.writeInteger(SSHMessage.IgnoreMessage.id)
            writtenBytes += self.writeIgnoreMessage(message)
        case .unimplemented(let message):
            writtenBytes += self.writeInteger(SSHMessage.UnimplementedMessage.id)
            writtenBytes += self.writeUnimplementedMessage(message)
        case .debug(let message):
            writtenBytes += self.writeInteger(SSHMessage.DebugMessage.id)
            writtenBytes += self.writeDebugMessage(message)
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
            writtenBytes += self.writeInteger(SSHMessage.UserAuthSuccessMessage.id)
        case .userAuthBanner(let message):
            writtenBytes += self.writeInteger(SSHMessage.UserAuthBannerMessage.id)
            writtenBytes += self.writeUserAuthBannerMessage(message)
        case .userAuthPKOK(let message):
            writtenBytes += self.writeInteger(SSHMessage.UserAuthPKOKMessage.id)
            writtenBytes += self.writeUserAuthPKOKMessage(message)
        case .globalRequest(let message):
            writtenBytes += self.writeInteger(SSHMessage.GlobalRequestMessage.id)
            writtenBytes += self.writeGlobalRequestMessage(message)
        case .requestSuccess(let message):
            writtenBytes += self.writeInteger(SSHMessage.RequestSuccessMessage.id)
            writtenBytes += self.writeRequestSuccessMessage(message)
        case .requestFailure:
            writtenBytes += self.writeInteger(SSHMessage.RequestFailureMessage.id)
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
        var writtenBytes = 0
        writtenBytes += self.writeInteger(message.reason)
        writtenBytes += self.writeSSHString(message.description.utf8)
        writtenBytes += self.writeSSHString(message.tag.utf8)
        return writtenBytes
    }

    mutating func writeIgnoreMessage(_ message: SSHMessage.IgnoreMessage) -> Int {
        var message = message
        return self.writeSSHString(&message.data)
    }

    mutating func writeUnimplementedMessage(_ message: SSHMessage.UnimplementedMessage) -> Int {
        self.writeInteger(message.sequenceNumber)
    }

    mutating func writeDebugMessage(_ message: SSHMessage.DebugMessage) -> Int {
        var written = self.writeSSHBoolean(message.alwaysDisplay)
        written += self.writeSSHString(message.message.utf8)
        written += self.writeSSHString(message.language.utf8)
        return written
    }

    mutating func writeServiceRequestMessage(_ message: SSHMessage.ServiceRequestMessage) -> Int {
        self.writeSSHString(message.service.utf8)
    }

    mutating func writeServiceAcceptMessage(_ message: SSHMessage.ServiceAcceptMessage) -> Int {
        self.writeSSHString(message.service.utf8)
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
        self.writeSSHString(algorithms.joined(separator: ",").utf8)
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
        case .publicKey(.known(key: let key, signature: let signature)):
            writtenBytes += self.writeSSHString("publickey".utf8)
            writtenBytes += self.writeSSHBoolean(signature != nil)
            writtenBytes += self.writeSSHString(key.keyPrefix)
            writtenBytes += self.writeCompositeSSHString { buffer in
                buffer.writeSSHHostKey(key)
            }

            if let signature = signature {
                writtenBytes += self.writeCompositeSSHString { buffer in
                    buffer.writeSSHSignature(signature)
                }
            }

        case .publicKey(.unknown):
            preconditionFailure("We cannot write user auth request messages on unknown keys")
        }

        return writtenBytes
    }

    mutating func writeUserAuthFailureMessage(_ message: SSHMessage.UserAuthFailureMessage) -> Int {
        var writtenBytes = 0
        writtenBytes += self.writeAlgorithms(message.authentications)
        writtenBytes += self.writeSSHBoolean(message.partialSuccess)
        return writtenBytes
    }

    mutating func writeUserAuthBannerMessage(_ message: SSHMessage.UserAuthBannerMessage) -> Int {
        var writtenBytes = 0
        writtenBytes += self.writeSSHString(message.message.utf8)
        writtenBytes += self.writeSSHString(message.languageTag.utf8)
        return writtenBytes
    }

    mutating func writeUserAuthPKOKMessage(_ message: SSHMessage.UserAuthPKOKMessage) -> Int {
        var writtenBytes = 0
        writtenBytes += self.writeSSHString(message.key.keyPrefix)
        writtenBytes += self.writeCompositeSSHString { buffer in
            buffer.writeSSHHostKey(message.key)
        }
        return writtenBytes
    }

    mutating func writeGlobalRequestMessage(_ message: SSHMessage.GlobalRequestMessage) -> Int {
        var writtenBytes = 0

        switch message.type {
        case .tcpipForward(let addressToBind, let port):
            writtenBytes += self.writeSSHString("tcpip-forward".utf8)
            writtenBytes += self.writeSSHBoolean(message.wantReply)
            writtenBytes += self.writeSSHString(addressToBind.utf8)
            writtenBytes += self.writeInteger(port)
        case .cancelTcpipForward(let addressToBind, let port):
            writtenBytes += self.writeSSHString("cancel-tcpip-forward".utf8)
            writtenBytes += self.writeSSHBoolean(message.wantReply)
            writtenBytes += self.writeSSHString(addressToBind.utf8)
            writtenBytes += self.writeInteger(port)
        case .unknown(let requestType, var payload):
            writtenBytes += self.writeSSHString(requestType.utf8)
            writtenBytes += self.writeSSHBoolean(message.wantReply)
            writtenBytes += self.writeBuffer(&payload)
        }

        return writtenBytes
    }

    mutating func writeRequestSuccessMessage(_ message: SSHMessage.RequestSuccessMessage) -> Int {
        var data = message.buffer
        return self.writeBuffer(&data)
    }

    mutating func writeChannelOpenMessage(_ message: SSHMessage.ChannelOpenMessage) -> Int {
        var writtenBytes = 0

        switch message.type {
        case .session:
            writtenBytes += self.writeSSHString("session".utf8)

        case .forwardedTCPIP:
            writtenBytes += self.writeSSHString("forwarded-tcpip".utf8)

        case .directTCPIP:
            writtenBytes += self.writeSSHString("direct-tcpip".utf8)
        }

        writtenBytes += self.writeInteger(message.senderChannel)
        writtenBytes += self.writeInteger(message.initialWindowSize)
        writtenBytes += self.writeInteger(message.maximumPacketSize)

        switch message.type {
        case .session:
            break

        case .forwardedTCPIP(let data):
            // We'll write gibberish if we can't get IP addresses out
            writtenBytes += self.writeSSHString(data.hostListening.utf8)
            writtenBytes += self.writeInteger(UInt32(data.portListening))
            writtenBytes += self.writeSSHString((data.originatorAddress.ipAddress ?? "<nio-error>").utf8)
            writtenBytes += self.writeInteger(UInt32(data.originatorAddress.port ?? -1))

        case .directTCPIP(let data):
            // We'll write gibberish if we can't get IP addresses out
            writtenBytes += self.writeSSHString(data.hostToConnectTo.utf8)
            writtenBytes += self.writeInteger(UInt32(data.portToConnectTo))
            writtenBytes += self.writeSSHString((data.originatorAddress.ipAddress ?? "<nio-error>").utf8)
            writtenBytes += self.writeInteger(UInt32(data.originatorAddress.port ?? -1))
        }

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
        case .exitStatus:
            writtenBytes += self.writeSSHString("exit-status".utf8)
        case .exitSignal:
            writtenBytes += self.writeSSHString("exit-signal".utf8)
        case .ptyReq:
            writtenBytes += self.writeSSHString("pty-req".utf8)
        case .shell:
            writtenBytes += self.writeSSHString("shell".utf8)
        case .subsystem:
            writtenBytes += self.writeSSHString("subsystem".utf8)
        case .windowChange:
            writtenBytes += self.writeSSHString("window-change".utf8)
        case .xonXoff:
            writtenBytes += self.writeSSHString("xon-xoff".utf8)
        case .signal:
            writtenBytes += self.writeSSHString("signal".utf8)
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
        case .exitStatus(let status):
            writtenBytes += self.writeInteger(status)
        case .exitSignal(let name, let coreDumped, let errorMessage, let language):
            writtenBytes += self.writeSSHString(name.utf8)
            writtenBytes += self.writeSSHBoolean(coreDumped)
            writtenBytes += self.writeSSHString(errorMessage.utf8)
            writtenBytes += self.writeSSHString(language.utf8)
        case .ptyReq(let message):
            writtenBytes += self.writeSSHString(message.termVariable.utf8)
            writtenBytes += self.writeInteger(message.characterWidth)
            writtenBytes += self.writeInteger(message.rowHeight)
            writtenBytes += self.writeInteger(message.pixelWidth)
            writtenBytes += self.writeInteger(message.pixelHeight)
            writtenBytes += self.writeCompositeSSHString { $0.writeSSHTerminalModes(message.terminalModes) }
        case .shell:
            break
        case .subsystem(let name):
            writtenBytes += self.writeSSHString(name.utf8)
        case .windowChange(let message):
            writtenBytes += self.writeInteger(message.characterWidth)
            writtenBytes += self.writeInteger(message.rowHeight)
            writtenBytes += self.writeInteger(message.pixelWidth)
            writtenBytes += self.writeInteger(message.pixelHeight)
        case .xonXoff(let clientCanDo):
            writtenBytes += self.writeSSHBoolean(clientCanDo)
        case .signal(let name):
            writtenBytes += self.writeSSHString(name.utf8)
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

// MARK: - MultiMessage

/// `SSHMultiMessage` is a representation of one or more SSH messages. This wide struct is used
/// to avoid allocating arrays internally in cases where we may need to represent multiple messages
/// that conceptually move "together". This can occur, for example, in SSH key exchange where both
/// keyExchangeReply and newKeys messages may want to be sent at once.
///
/// The number of messages this can hold is strictly limited to the number of messages we need it to be
/// able to, in order to keep sizes down.
///
/// This collection is never _empty_: if you have one, there must be at least one message in it. This is a
/// convenience feature that ensures that we know that the presence of this object implies the existence of
/// at least one message.
internal struct SSHMultiMessage {
    private var _first: SSHMessage

    private var _second: SSHMessage?

    private var _count: UInt8

    init(_ first: SSHMessage, _ second: SSHMessage? = nil) {
        self._first = first
        self._second = second

        switch self._second {
        case .none:
            self._count = 1
        case .some:
            self._count = 2
        }
    }
}

extension SSHMultiMessage: RandomAccessCollection {
    struct Index {
        fileprivate var _baseIndex: UInt8

        init(_ baseIndex: UInt8) {
            self._baseIndex = baseIndex
        }
    }

    var startIndex: Index {
        Index(0)
    }

    var endIndex: Index {
        Index(self._count)
    }

    var count: Int {
        Int(self._count)
    }

    var first: SSHMessage? {
        self._first
    }

    subscript(position: Index) -> SSHMessage {
        switch position._baseIndex {
        case 0:
            return self._first
        case 1:
            return self._second!
        default:
            preconditionFailure("Index \(position) is invalid")
        }
    }
}

extension SSHMultiMessage.Index: Equatable {}

extension SSHMultiMessage.Index: Comparable {
    static func < (lhs: Self, rhs: Self) -> Bool {
        lhs._baseIndex < rhs._baseIndex
    }
}

// We use Int as a stride type here just because it's easier.
extension SSHMultiMessage.Index: Strideable {
    func advanced(by n: Int) -> SSHMultiMessage.Index {
        Self(UInt8(Int(self._baseIndex) + n))
    }

    func distance(to other: SSHMultiMessage.Index) -> Int {
        Int(other._baseIndex - self._baseIndex)
    }
}

extension SSHMultiMessage: Equatable {}
