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

/// An SSH private key.
///
/// This object identifies a single SSH entity, usually a server. It is used as part of the SSH handshake and key exchange process,
/// and is also presented to clients that want to validate that they are communicating with the appropriate server. Clients use
/// this key to sign data in order to validate their identity as part of user auth.
///
/// Users cannot do much with this key other than construct it, but NIO uses it internally.
public struct NIOSSHPrivateKey: Sendable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: NIOSSHPrivateKeyProtocol

    private init(backingKey: NIOSSHPrivateKeyProtocol) {
        self.backingKey = backingKey
    }

    public init(ed25519Key key: Curve25519.Signing.PrivateKey) {
        self.backingKey = key
    }

    public init(p256Key key: P256.Signing.PrivateKey) {
        self.backingKey = key
    }

    public init(p384Key key: P384.Signing.PrivateKey) {
        self.backingKey = key
    }

    public init(p521Key key: P521.Signing.PrivateKey) {
        self.backingKey = key
    }

    #if canImport(Darwin)
    public init(secureEnclaveP256Key key: SecureEnclave.P256.Signing.PrivateKey) {
        self.backingKey = key
    }
    #endif

    // The algorithms that apply to this host key.
    internal var hostKeyAlgorithms: [Substring] {
        return [ Substring(backingKey.keyPrefix) ]
    }
}

extension NIOSSHPrivateKey {
    func sign<DigestBytes: Digest>(digest: DigestBytes) throws -> NIOSSHSignature {
        return try digest.withUnsafeBytes { ptr in
            try backingKey.sshSignature(for: ptr)
        }
    }

    func sign(_ payload: UserAuthSignablePayload) throws -> NIOSSHSignature {
        return try backingKey.sshSignature(for: payload.bytes.readableBytesView)
    }
}

extension NIOSSHPrivateKey {
    /// Obtains the public key for a corresponding private key.
    public var publicKey: NIOSSHPublicKey {
        NIOSSHPublicKey(backingKey: backingKey.sshPublicKey)
    }
}
