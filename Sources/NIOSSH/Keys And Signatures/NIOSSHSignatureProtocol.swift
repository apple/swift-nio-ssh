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

/// A signature is a mathematical scheme for verifying the authenticity of digital messages or documents.
///
/// This protocol can be implemented by a type that represents such a signature to NIOSSH.
///
/// - See: https://en.wikipedia.org/wiki/Digital_signature
public protocol NIOSSHSignatureProtocol: Sendable {
    /// An identifier that represents the type of signature used in an SSH packet.
    /// This identifier MUST be unique to the signature implementation.
    /// The returned value MUST NOT overlap with other signature implementations or a specifications that the signature does not implement.
    static var signaturePrefix: String { get }

    /// The raw reprentation of this signature as a blob.
    var rawRepresentation: Data { get }

    /// Serializes and writes the signature to the buffer. The calling function SHOULD NOT keep track of the size of the written blob.
    /// If the result is not a fixed size, the serialized format SHOULD include a length.
    func write(to buffer: inout ByteBuffer) -> Int

    /// Reads this Signature from the buffer using the same format implemented in `write(to:)`
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

internal extension NIOSSHSignatureProtocol {
    var signaturePrefix: String {
        Self.signaturePrefix
    }
}