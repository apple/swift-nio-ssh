//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import NIOFoundationCompat

/// This protocol represents a public key that is capable of performing an ECDH key exchange in SSH.
///
/// We use this protocol to abstract the various portions of the ECDH key exchange that are key-specific
/// while keeping common the various protocol elements that don't vary.
protocol ECDHCompatiblePublicKey {
    /// Construct a copy of this key from a `ByteBuffer`.
    init(buffer: ByteBuffer) throws

    /// Write a copy of the public key bytes to a `ByteBuffer`
    @discardableResult
    func write(to: inout ByteBuffer) -> Int
}

/// This protocol represents a private key that is capable of performing an ECDH key exchange in SSH.
///
/// We use this protocol to abstract the various portions of the ECDH key exchange that are key-specific
/// while keeping common the various protocol elements that don't vary.
protocol ECDHCompatiblePrivateKey {
    associatedtype PublicKey: ECDHCompatiblePublicKey

    associatedtype Hasher: HashFunction

    init()

    var publicKey: PublicKey { get }

    func generatedSharedSecret(with: PublicKey) throws -> SharedSecret

    static var keyExchangeAlgorithmNames: [Substring] { get }
}

// MARK: Conformances

extension Curve25519.KeyAgreement.PublicKey: ECDHCompatiblePublicKey {
    init(buffer keyBytes: ByteBuffer) throws {
        // Curve25519 keys are essentially unstructured bags of bytes. It's great.
        self = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyBytes.readableBytesView)
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        // Curve25519 keys are essentially unstructured bags of bytes. It's great.
        buffer.writeContiguousBytes(self.rawRepresentation)
    }
}

extension Curve25519.KeyAgreement.PrivateKey: ECDHCompatiblePrivateKey {
    typealias Hasher = SHA256

    func generatedSharedSecret(with other: Curve25519.KeyAgreement.PublicKey) throws -> SharedSecret {
        let sharedSecret = try self.sharedSecretFromKeyAgreement(with: other)
        guard sharedSecret.isStrongSecret else {
            throw NIOSSHError.weakSharedSecret(exchangeAlgorithm: "Curve25519")
        }
        return sharedSecret
    }

    static let keyExchangeAlgorithmNames: [Substring] = ["curve25519-sha256", "curve25519-sha256@libssh.org"]
}

extension P256.KeyAgreement.PublicKey: ECDHCompatiblePublicKey {
    init(buffer keyBytes: ByteBuffer) throws {
        self = try P256.KeyAgreement.PublicKey(x963Representation: keyBytes.readableBytesView)
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeContiguousBytes(self.x963Representation)
    }
}

extension P256.KeyAgreement.PrivateKey: ECDHCompatiblePrivateKey {
    init() {
        self = .init(compactRepresentable: false)
    }

    typealias Hasher = SHA256

    func generatedSharedSecret(with other: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try self.sharedSecretFromKeyAgreement(with: other)
    }

    static let keyExchangeAlgorithmNames: [Substring] = ["ecdh-sha2-nistp256"]
}

extension P384.KeyAgreement.PublicKey: ECDHCompatiblePublicKey {
    init(buffer keyBytes: ByteBuffer) throws {
        self = try P384.KeyAgreement.PublicKey(x963Representation: keyBytes.readableBytesView)
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeContiguousBytes(self.x963Representation)
    }
}

extension P384.KeyAgreement.PrivateKey: ECDHCompatiblePrivateKey {
    init() {
        self = .init(compactRepresentable: false)
    }

    typealias Hasher = SHA384

    func generatedSharedSecret(with other: P384.KeyAgreement.PublicKey) throws -> SharedSecret {
        try self.sharedSecretFromKeyAgreement(with: other)
    }

    static let keyExchangeAlgorithmNames: [Substring] = ["ecdh-sha2-nistp384"]
}

extension P521.KeyAgreement.PublicKey: ECDHCompatiblePublicKey {
    init(buffer keyBytes: ByteBuffer) throws {
        self = try P521.KeyAgreement.PublicKey(x963Representation: keyBytes.readableBytesView)
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeContiguousBytes(self.x963Representation)
    }
}

extension P521.KeyAgreement.PrivateKey: ECDHCompatiblePrivateKey {
    init() {
        self = .init(compactRepresentable: false)
    }

    typealias Hasher = SHA512

    func generatedSharedSecret(with other: P521.KeyAgreement.PublicKey) throws -> SharedSecret {
        try self.sharedSecretFromKeyAgreement(with: other)
    }

    static let keyExchangeAlgorithmNames: [Substring] = ["ecdh-sha2-nistp521"]
}

// MARK: Helpers

extension SharedSecret {
    /// In Curve25519 we need to check for the possibility that the peer's key is a point of low order.
    /// If it is, we will end up generating the all-zero shared secret, which is pretty not good.
    /// This property is `true` if the secret is strong, and `false` if it is not.
    fileprivate var isStrongSecret: Bool {
        // CryptoKit doesn't want to let us look directly at this, so we need to exfiltrate a pointer.
        // For the sake of avoiding leaking information about the secret, we choose to do this in constant
        // time by ORing every byte together: if the result is zero, this point is invalid.
        self.withUnsafeBytes { dataPtr in
            let allORed = dataPtr.reduce(UInt8(0)) { $0 | $1 }
            return allORed != 0
        }
    }
}
