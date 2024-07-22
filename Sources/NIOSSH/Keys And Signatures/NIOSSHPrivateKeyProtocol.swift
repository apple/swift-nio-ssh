//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore

public protocol NIOSSHPrivateKeyProtocol: Sendable {
    /// An identifier that represents the type of private key used in an SSH packet.
    /// This identifier MUST be unique to the private key implementation.
    /// The returned value MUST NOT overlap with other private key implementations or a specifications that the private key does not implement.
    static var keyPrefix: String { get }

    /// A public key instance that is able to verify signatures that are created using this private key.
    var sshPublicKey: NIOSSHPublicKeyProtocol { get }

    /// Creates a signature, proving that `data` has been sent by the holder of this private key, and can be verified by `publicKey`.
    func sshSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignature
}

internal extension NIOSSHPrivateKeyProtocol {
    var keyPrefix: String {
        Self.keyPrefix
    }
}
