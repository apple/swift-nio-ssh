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
import Crypto

/// An SSH server host private key.
///
/// This object identifies a single SSH server. It is used as part of the SSH handshake and key exchange process,
/// and is also presented to clients that want to validate that they are communicating with the appropriate server.
///
/// Users cannot do much with this key, but NIO uses it internally.
public struct NIOSSHHostPrivateKey {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: BackingKey

    fileprivate init(backingKey: BackingKey) {
        self.backingKey = backingKey
    }

    public init(ed25519Key key: Curve25519.Signing.PrivateKey) {
        self.backingKey = .ed25519(key)
    }

    public init(p256Key key: P256.Signing.PrivateKey) {
        self.backingKey = .ecdsaP256(key)
    }
}


extension NIOSSHHostPrivateKey {
    /// The various key types that can be used with NIOSSH.
    internal enum BackingKey {
        case ed25519(Curve25519.Signing.PrivateKey)
        case ecdsaP256(P256.Signing.PrivateKey)
    }
}


extension NIOSSHHostPrivateKey {
    func sign<DigestBytes: Digest>(digest: DigestBytes) throws -> SSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return SSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            return try SSHSignature(backingSignature: .ecdsaP256(key.signature(for: digest)))
        }
    }
}


extension NIOSSHHostPrivateKey {
    /// Obtains the public key for a corresponding private key.
    internal var publicKey: NIOSSHHostPublicKey {
        switch self.backingKey {
        case .ed25519(let privateKey):
            return NIOSSHHostPublicKey(backingKey: .ed25519(privateKey.publicKey))
        case .ecdsaP256(let privateKey):
            return NIOSSHHostPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        }
    }
}
