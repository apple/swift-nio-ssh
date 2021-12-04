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

/// An error thrown by NIOSSH.
///
/// For extensibility purposes, `NIOSSHError`s are composed of two parts. The first part is an
/// error type. This is like an enum, but extensible, and identifies the kind of error programmatically.
/// The second part is some opaque diagnostic data. This is not visible to your code, but is used to
/// help provide extra information for diagnostic purposes when logging this error.
///
/// Note that due to this construction `NIOSSHError` is not equatable: only the `type` is. This is deliberate,
/// as it is possible two errors have the same type but a different underlying cause or diagnostic data. For
/// this reason, if you need to compare two `NIOSSHError` values you should explicitly compare their `type`.
public struct NIOSSHError: Error {
    public var type: ErrorType

    private var diagnostics: String?
}

// MARK: - Internal helper functions for error construction.

// These are never inlined as they are inherently cold path functions.
extension NIOSSHError {
    @inline(never)
    internal static func invalidSSHMessage(reason: String) -> NIOSSHError {
        NIOSSHError(type: .invalidSSHMessage, diagnostics: reason)
    }

    @inline(never)
    internal static func weakSharedSecret(exchangeAlgorithm: String) -> NIOSSHError {
        NIOSSHError(type: .weakSharedSecret, diagnostics: exchangeAlgorithm)
    }

    internal static let invalidNonceLength = NIOSSHError(type: .invalidNonceLength, diagnostics: nil)

    internal static let excessiveVersionLength = NIOSSHError(type: .excessiveVersionLength, diagnostics: nil)

    internal static let invalidEncryptedPacketLength = NIOSSHError(type: .invalidEncryptedPacketLength, diagnostics: nil)

    internal static let invalidDecryptedPlaintextLength = NIOSSHError(type: .invalidDecryptedPlaintextLength, diagnostics: nil)

    internal static let invalidKeySize = NIOSSHError(type: .invalidKeySize, diagnostics: nil)

    internal static let insufficientPadding = NIOSSHError(type: .insufficientPadding, diagnostics: nil)

    internal static let excessPadding = NIOSSHError(type: .excessPadding, diagnostics: nil)

    @inline(never)
    internal static func unknownPublicKey(algorithm: String) -> NIOSSHError {
        NIOSSHError(type: .unknownPublicKey, diagnostics: algorithm)
    }

    @inline(never)
    internal static func unknownSignature(algorithm: String) -> NIOSSHError {
        NIOSSHError(type: .unknownSignature, diagnostics: algorithm)
    }

    @inline(never)
    internal static func invalidDomainParametersForKey(parameters: String) -> NIOSSHError {
        NIOSSHError(type: .invalidDomainParametersForKey, diagnostics: parameters)
    }

    internal static let invalidExchangeHashSignature = NIOSSHError(type: .invalidExchangeHashSignature, diagnostics: nil)

    internal static let invalidPacketFormat = NIOSSHError(type: .invalidPacketFormat, diagnostics: nil)

    @inline(never)
    internal static func protocolViolation(protocolName: String, violation: String) -> NIOSSHError {
        NIOSSHError(type: .protocolViolation, diagnostics: "Protocol \(protocolName) violated due to \(violation)")
    }

    internal static let keyExchangeNegotiationFailure = NIOSSHError(type: .keyExchangeNegotiationFailure, diagnostics: nil)

    @inline(never)
    internal static func unsupportedVersion(_ version: String) -> NIOSSHError {
        NIOSSHError(type: .unsupportedVersion, diagnostics: "Version \(version) offered by the remote peer is not supported")
    }

    @inline(never)
    internal static func channelSetupRejected(reasonCode: UInt32, reason: String) -> NIOSSHError {
        NIOSSHError(type: .channelSetupRejected, diagnostics: "Reason: \(reasonCode) \(reason)")
    }

    @inline(never)
    internal static func flowControlViolation(currentWindow: UInt32, increment: UInt32) -> NIOSSHError {
        NIOSSHError(type: .flowControlViolation, diagnostics: "Window size \(currentWindow), bad increment \(increment)")
    }

    internal static let creatingChannelAfterClosure = NIOSSHError(type: .creatingChannelAfterClosure, diagnostics: nil)

    internal static let tcpShutdown = NIOSSHError(type: .tcpShutdown, diagnostics: nil)

    internal static let invalidUserAuthSignature = NIOSSHError(type: .invalidUserAuthSignature, diagnostics: nil)

    @inline(never)
    internal static func unknownPacketType(diagnostic: String) -> NIOSSHError {
        NIOSSHError(type: .unknownPacketType, diagnostics: diagnostic)
    }

    internal static let unsupportedGlobalRequest = NIOSSHError(type: .unsupportedGlobalRequest, diagnostics: nil)

    internal static let unexpectedGlobalRequestResponse = NIOSSHError(type: .unexpectedGlobalRequestResponse, diagnostics: nil)

    internal static let missingGlobalRequestResponse = NIOSSHError(type: .missingGlobalRequestResponse, diagnostics: nil)

    internal static let globalRequestRefused = NIOSSHError(type: .globalRequestRefused, diagnostics: nil)

    @inline(never)
    internal static func remotePeerDoesNotSupportMessage(_ message: SSHMessage.UnimplementedMessage) -> NIOSSHError {
        NIOSSHError(type: .remotePeerDoesNotSupportMessage, diagnostics: "Sequence Number: \(message.sequenceNumber)")
    }

    @inline(never)
    internal static func invalidHostKeyForKeyExchange(expected: Substring, got actual: String.UTF8View) -> NIOSSHError {
        NIOSSHError(type: .invalidHostKeyForKeyExchange, diagnostics: "Expected \(String(expected)), got \(String(actual))")
    }

    @inline(never)
    internal static func invalidOpenSSHPublicKey(reason: String) -> NIOSSHError {
        NIOSSHError(type: .invalidOpenSSHPublicKey, diagnostics: reason)
    }

    @inline(never)
    internal static func invalidCertificate(diagnostics: String) -> NIOSSHError {
        NIOSSHError(type: .invalidCertificate, diagnostics: diagnostics)
    }
}

// MARK: - NIOSSHError CustomStringConvertible conformance.

extension NIOSSHError: CustomStringConvertible {
    public var description: String {
        "NIOSSHError.\(self.type.description)\(self.diagnostics.map { ": \($0)" } ?? "")"
    }
}

// MARK: - Definition of NIOSSHError.ErrorType

extension NIOSSHError {
    /// The types of NIOSSHError that can be encountered.
    public struct ErrorType {
        private enum Base: Hashable {
            case invalidSSHMessage
            case weakSharedSecret
            case invalidNonceLength
            case invalidEncryptedPacketLength
            case invalidDecryptedPlaintextLength
            case invalidKeySize
            case insufficientPadding
            case excessPadding
            case unknownPublicKey
            case unknownSignature
            case invalidDomainParametersForKey
            case invalidExchangeHashSignature
            case invalidPacketFormat
            case protocolViolation
            case keyExchangeNegotiationFailure
            case unsupportedVersion
            case channelSetupRejected
            case flowControlViolation
            case creatingChannelAfterClosure
            case tcpShutdown
            case invalidUserAuthSignature
            case unknownPacketType
            case unsupportedGlobalRequest
            case unexpectedGlobalRequestResponse
            case globalRequestRefused
            case missingGlobalRequestResponse
            case remotePeerDoesNotSupportMessage
            case invalidHostKeyForKeyExchange
            case invalidOpenSSHPublicKey
            case invalidCertificate
            case excessiveVersionLength
        }

        private var base: Base

        private init(_ base: Base) {
            self.base = base
        }

        /// An invalid SSH message was received.
        public static let invalidSSHMessage: ErrorType = .init(.invalidSSHMessage)

        /// The key exchange process generated a weak shared secret.
        public static let weakSharedSecret: ErrorType = .init(.weakSharedSecret)

        /// The length of the nonce provided to a cipher is invalid for that cipher.
        public static let invalidNonceLength: ErrorType = .init(.invalidNonceLength)

        /// The version length sent by a client was excessively large.
        public static let excessiveVersionLength: ErrorType = .init(.excessiveVersionLength)

        /// The encrypted packet received has an invalid length for the negotiated encyption scheme
        public static let invalidEncryptedPacketLength: ErrorType = .init(.invalidEncryptedPacketLength)

        /// The decrypted plaintext length is not a multiple of the block size.
        public static let invalidDecryptedPlaintextLength: ErrorType = .init(.invalidDecryptedPlaintextLength)

        /// The generated key size was invalid for the given encryption scheme.
        public static let invalidKeySize: ErrorType = .init(.invalidKeySize)

        /// A packet was decrypted that had insufficient padding.
        public static let insufficientPadding: ErrorType = .init(.insufficientPadding)

        /// More padding bytes were supposed to be present than actually are present in a packet.
        public static let excessPadding: ErrorType = .init(.excessPadding)

        /// The public key type provided is not recognised.
        public static let unknownPublicKey: ErrorType = .init(.unknownPublicKey)

        /// The signature type provided is not recognised.
        public static let unknownSignature: ErrorType = .init(.unknownSignature)

        /// A public key was parsed that has invalid domain parameters for the given key type.
        public static let invalidDomainParametersForKey: ErrorType = .init(.invalidDomainParametersForKey)

        /// The signature over the exchange hash could not be validated.
        public static let invalidExchangeHashSignature: ErrorType = .init(.invalidExchangeHashSignature)

        /// The packet format is invalid.
        public static let invalidPacketFormat: ErrorType = .init(.invalidPacketFormat)

        /// One of the SSH protocols was violated.
        public static let protocolViolation: ErrorType = .init(.protocolViolation)

        /// No suitable key exchange negotiation protocols were found.
        public static let keyExchangeNegotiationFailure: ErrorType = .init(.keyExchangeNegotiationFailure)

        /// The SSH version offered by the remote peer is unsupported by this implementation.
        public static let unsupportedVersion: ErrorType = .init(.unsupportedVersion)

        /// The remote peer rejected a request to setup a new channel.
        public static let channelSetupRejected: ErrorType = .init(.channelSetupRejected)

        /// The remote peer violated the SSH flow control rules.
        public static let flowControlViolation: ErrorType = .init(.flowControlViolation)

        /// The user attempted to create an SSH channel after the SSH handler was closed.
        public static let creatingChannelAfterClosure: ErrorType = .init(.creatingChannelAfterClosure)

        /// The TCP connection was shut down without cleanly closing the SSH channel.
        public static let tcpShutdown: ErrorType = .init(.tcpShutdown)

        /// The signature provided in user authentication was invalid.
        public static let invalidUserAuthSignature: ErrorType = .init(.invalidUserAuthSignature)

        /// An packet type that we don't recognise was received.
        public static let unknownPacketType: ErrorType = .init(.unknownPacketType)

        /// A global request was made and rejected due to being unsupported.
        public static let unsupportedGlobalRequest: ErrorType = .init(.unsupportedGlobalRequest)

        /// We received a response to a global request that we were not expecting.
        public static let unexpectedGlobalRequestResponse: ErrorType = .init(.unexpectedGlobalRequestResponse)

        /// We didn't receive a response to a global request, but were expecting one
        public static let missingGlobalRequestResponse: ErrorType = .init(.missingGlobalRequestResponse)

        /// A global request was refused by the peer.
        public static let globalRequestRefused: ErrorType = .init(.globalRequestRefused)

        /// The remote peer sent an "unimplemented" message, indicating they do not support a message we sent.
        public static let remotePeerDoesNotSupportMessage: ErrorType = .init(.remotePeerDoesNotSupportMessage)

        /// The peer has sent a host key that does not correspond to the one negotiated in key exchange.
        public static let invalidHostKeyForKeyExchange: ErrorType = .init(.invalidHostKeyForKeyExchange)

        /// The OpenSSH public key string could not be parsed.
        public static let invalidOpenSSHPublicKey: ErrorType = .init(.invalidOpenSSHPublicKey)

        /// A certificate failed validation.
        public static let invalidCertificate: ErrorType = .init(.invalidCertificate)
    }
}

// MARK: - NIOSSHError.ErrorType Hashable conformance

extension NIOSSHError.ErrorType: Hashable {}

// MARK: - NIOSSHError.ErrorType CustomStringConvertible conformance

extension NIOSSHError.ErrorType: CustomStringConvertible {
    public var description: String {
        String(describing: self.base)
    }
}
