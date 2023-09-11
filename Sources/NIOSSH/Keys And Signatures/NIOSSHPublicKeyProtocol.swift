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

public protocol NIOSSHPublicKeyProtocol: Sendable {
    /// An identifier that represents the type of public key used in an SSH packet.
    /// This identifier MUST be unique to the public key implementation.
    /// The returned value MUST NOT overlap with other public key implementations or a specifications that the public key does not implement.
    static var publicKeyPrefix: String? { get }
    var publicKeyPrefix: String { get }

    /// The raw reprentation of this publc key as a blob.
    var rawRepresentation: Data { get }

    /// Verifies that `signature` is the result of signing `data` using the private key that this public key is derived from.
    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignature, for data: D) -> Bool

    /// Serializes and writes the public key to the buffer. The calling function SHOULD NOT keep track of the size of the written blob.
    /// If the result is not a fixed size, the serialized format SHOULD include a length.
    func write(to buffer: inout ByteBuffer) -> Int
    
    func writeHostKey(to buffer: inout ByteBuffer) -> Int

    /// Reads this Public Key from the buffer using the same format implemented in `write(to:)`
    static func read(from buffer: inout ByteBuffer) throws -> Self?
}