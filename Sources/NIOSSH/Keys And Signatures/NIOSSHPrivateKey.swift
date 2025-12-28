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
import _CryptoExtras
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

    /// Create a private key from an RSA key.
    ///
    /// RSA support is provided for interoperability with legacy systems. For new deployments,
    /// consider using Ed25519 or ECDSA keys instead.
    public init(rsaKey key: _RSA.Signing.PrivateKey) {
        self.backingKey = .rsa(key)
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
        case .rsa:
            // Modern servers prefer rsa-sha2-512 > rsa-sha2-256 > ssh-rsa
            // ssh-rsa uses SHA-1 which is deprecated but still needed for compatibility
            return ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
        #if canImport(Darwin)
        case .secureEnclaveP256:
            return ["ecdsa-sha2-nistp256"]
        #endif
        }
    }
}

extension NIOSSHPrivateKey {
    /// The various key types that can be used with NIOSSH.
    internal enum BackingKey: @unchecked Sendable {
        case ed25519(Curve25519.Signing.PrivateKey)
        case ecdsaP256(P256.Signing.PrivateKey)
        case ecdsaP384(P384.Signing.PrivateKey)
        case ecdsaP521(P521.Signing.PrivateKey)
        case rsa(_RSA.Signing.PrivateKey)

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
        case .rsa(let key):
            // For RSA, we sign the digest using SHA-512 (rsa-sha2-512)
            let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA512(signature))

        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }

    func sign(_ payload: UserAuthSignablePayload, rsaSignatureAlgorithm: RSASignatureAlgorithm = .sha512) throws -> NIOSSHSignature {
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
        case .rsa(let key):
            // Sign using the specified RSA algorithm (RFC 8332)
            let data = Data(payload.bytes.readableBytesView)
            switch rsaSignatureAlgorithm {
            case .sha512:
                let digest = SHA512.hash(data: data)
                let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
                return NIOSSHSignature(backingSignature: .rsaSHA512(signature))
            case .sha256:
                let digest = SHA256.hash(data: data)
                let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
                return NIOSSHSignature(backingSignature: .rsaSHA256(signature))
            case .sha1:
                let digest = Insecure.SHA1.hash(data: data)
                let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
                return NIOSSHSignature(backingSignature: .rsaSHA1(signature))
            }
        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }

    /// Sign a payload with a specific RSA signature algorithm.
    ///
    /// This is used when the server negotiates a specific RSA algorithm (ssh-rsa, rsa-sha2-256, rsa-sha2-512).
    func signRSA(_ payload: UserAuthSignablePayload, algorithm: Substring) throws -> NIOSSHSignature {
        guard case .rsa(let key) = self.backingKey else {
            preconditionFailure("signRSA called on non-RSA key")
        }

        let data = Data(payload.bytes.readableBytesView)

        switch algorithm {
        case "ssh-rsa":
            // ssh-rsa uses SHA-1 (deprecated but still used for compatibility)
            let digest = Insecure.SHA1.hash(data: data)
            let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA1(signature))
        case "rsa-sha2-256":
            let digest = SHA256.hash(data: data)
            let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA256(signature))
        case "rsa-sha2-512":
            let digest = SHA512.hash(data: data)
            let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA512(signature))
        default:
            preconditionFailure("Unknown RSA algorithm: \(algorithm)")
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
        case .rsa(let privateKey):
            return NIOSSHPublicKey(backingKey: .rsa(privateKey.publicKey))
        #if canImport(Darwin)
        case .secureEnclaveP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        #endif
        }
    }
}
