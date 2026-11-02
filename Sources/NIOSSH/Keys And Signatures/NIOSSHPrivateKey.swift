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

@preconcurrency import Crypto
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An SSH private key.
///
/// This object identifies a single SSH entity, usually a server. It is used as part of the SSH handshake and key exchange process,
/// and is also presented to clients that want to validate that they are communicating with the appropriate server. Clients use
/// this key to sign data in order to validate their identity as part of user auth.
///
/// Users cannot do much with this key other than construct it, but NIO uses it internally.
public struct NIOSSHPrivateKey: Sendable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: BackingKey

    private init(backingKey: BackingKey) {
        self.backingKey = backingKey
    }

    public init(ed25519Key key: Curve25519.Signing.PrivateKey) {
        self.backingKey = .ed25519(key)
    }

    public init(p256Key key: P256.Signing.PrivateKey) {
        self.backingKey = .ecdsaP256(key)
    }

    public init(p384Key key: P384.Signing.PrivateKey) {
        self.backingKey = .ecdsaP384(key)
    }

    public init(p521Key key: P521.Signing.PrivateKey) {
        self.backingKey = .ecdsaP521(key)
    }

    /// Create a private key backed by an external signer (e.g. ssh-agent).
    /// 
    /// Use this when private-key material is held outside NIOSSH. The signer receives raw
    /// `UserAuthSignablePayload` bytes and returns algorithm-specific signature bytes.
    /// 
    /// - Parameter signer: External signer implementation that provides signatures for `publicKey` using raw SSH user-auth payload bytes.
    /// - SeeAlso: ``NIOSSHExternalSigner`` for payload/signature format and threading requirements.
    /// - Important: `sign(payload:)` is called synchronously on NIO event-loop threads. Do not block or perform
    ///   long-running work inside the signer.
    public init(externalSigner signer: any NIOSSHExternalSigner) {
        self.backingKey = .external(signer)
    }
    
    #if canImport(Darwin)
    public init(secureEnclaveP256Key key: SecureEnclave.P256.Signing.PrivateKey) {
        self.backingKey = .secureEnclaveP256(key)
    }
    #endif

    // The algorithms that apply to this host key.
    internal var hostKeyAlgorithms: [Substring] {
        switch self.backingKey {
        case .ed25519:
            return ["ssh-ed25519"]
        case .ecdsaP256:
            return ["ecdsa-sha2-nistp256"]
        case .ecdsaP384:
            return ["ecdsa-sha2-nistp384"]
        case .ecdsaP521:
            return ["ecdsa-sha2-nistp521"]
        case .external(let signer):
            return [Substring(String(decoding: signer.publicKey.keyPrefix, as: UTF8.self))]
        #if canImport(Darwin)
        case .secureEnclaveP256:
            return ["ecdsa-sha2-nistp256"]
        #endif
        }
    }
}

extension NIOSSHPrivateKey {
    /// The various key types that can be used with NIOSSH.
    internal enum BackingKey {
        case ed25519(Curve25519.Signing.PrivateKey)
        case ecdsaP256(P256.Signing.PrivateKey)
        case ecdsaP384(P384.Signing.PrivateKey)
        case ecdsaP521(P521.Signing.PrivateKey)
        case external(any NIOSSHExternalSigner)

        #if canImport(Darwin)
        case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)
        #endif
    }
}

extension NIOSSHPrivateKey {
    func sign<DigestBytes: Digest>(digest: DigestBytes) throws -> NIOSSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        case .external:
            throw NIOSSHError.externalSignerDigestUnsupported

        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }

    func sign(_ payload: UserAuthSignablePayload) throws -> NIOSSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        case .external(let signer):
            let signatureBytes = try signer.sign(payload: payload.bytes)
            let keyPrefix = signer.publicKey.keyPrefix

            if keyPrefix.elementsEqual(NIOSSHPublicKey.ed25519PublicKeyPrefix) {
                // Ed25519 remains wrapped as a ByteBuffer
                return NIOSSHSignature(backingSignature: .ed25519(.byteBuffer(signatureBytes)))
            }
            if keyPrefix.elementsEqual(NIOSSHPublicKey.ecdsaP256PublicKeyPrefix) {
                // ECDSA initializers use readableBytesView (DataProtocol)
                return try NIOSSHSignature(
                    backingSignature: .ecdsaP256(.init(rawRepresentation: signatureBytes.readableBytesView))
                )
            }
            if keyPrefix.elementsEqual(NIOSSHPublicKey.ecdsaP384PublicKeyPrefix) {
                return try NIOSSHSignature(
                    backingSignature: .ecdsaP384(.init(rawRepresentation: signatureBytes.readableBytesView))
                )
            }
            if keyPrefix.elementsEqual(NIOSSHPublicKey.ecdsaP521PublicKeyPrefix) {
                return try NIOSSHSignature(
                    backingSignature: .ecdsaP521(.init(rawRepresentation: signatureBytes.readableBytesView))
                )
            }
            throw NIOSSHError.unknownSignature(
                algorithm: String(decoding: keyPrefix, as: UTF8.self)
            )
        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }
}

extension NIOSSHPrivateKey {
    /// Obtains the public key for a corresponding private key.
    public var publicKey: NIOSSHPublicKey {
        switch self.backingKey {
        case .ed25519(let privateKey):
            return NIOSSHPublicKey(backingKey: .ed25519(privateKey.publicKey))
        case .ecdsaP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        case .ecdsaP384(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP384(privateKey.publicKey))
        case .ecdsaP521(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP521(privateKey.publicKey))
        case .external(let signer):
            return signer.publicKey
        #if canImport(Darwin)
        case .secureEnclaveP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        #endif
        }
    }
}

/// External signer interface for SSH public-key authentication.
public protocol NIOSSHExternalSigner: Sendable {
    var publicKey: NIOSSHPublicKey { get }

    /// Signs the raw SSH user-auth payload.
    ///
    /// - Parameter payload: Raw `UserAuthSignablePayload` bytes
    ///   (session identifier + `SSH_MSG_USERAUTH_REQUEST` fields). The payload is **not** pre-hashed.
    /// - Returns: Signature bytes compatible with `publicKey`.
    ///
    /// Supported external signature encodings:
    /// - `ssh-ed25519`: raw Ed25519 signature bytes.
    /// - `ecdsa-sha2-nistp256`: CryptoKit P-256 `rawRepresentation` (`r || s`, fixed-width, 64 bytes).
    /// - `ecdsa-sha2-nistp384`: CryptoKit P-384 `rawRepresentation` (`r || s`, fixed-width, 96 bytes).
    /// - `ecdsa-sha2-nistp521`: CryptoKit P-521 `rawRepresentation` (`r || s`, fixed-width, 132 bytes).
    ///
    /// - Important: This is called synchronously on NIO event-loop threads. Implementations must not block.
    func sign(payload: ByteBuffer) throws -> ByteBuffer
}
