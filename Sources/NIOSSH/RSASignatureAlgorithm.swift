//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// The RSA signature algorithm to use for user authentication.
///
/// Per RFC 8332, servers may support different RSA signature algorithms.
/// Modern servers prefer rsa-sha2-512, but older servers may only support ssh-rsa.
public enum RSASignatureAlgorithm: Hashable, Sendable {
    /// RSA signature using SHA-512 (recommended, RFC 8332)
    case sha512
    
    /// RSA signature using SHA-256 (RFC 8332)
    case sha256
    
    /// RSA signature using SHA-1 (deprecated, legacy compatibility only)
    case sha1
    
    /// The algorithm name as used in SSH wire protocol
    public var algorithmName: String {
        switch self {
        case .sha512: return "rsa-sha2-512"
        case .sha256: return "rsa-sha2-256"
        case .sha1: return "ssh-rsa"
        }
    }
    
    /// The algorithm name as UTF8 bytes for wire protocol
    internal var wireBytes: String.UTF8View { self.algorithmName.utf8 }
    
    /// Initialize from wire protocol algorithm name.
    /// Returns nil for unrecognized algorithm names.
    public init?<Bytes: Collection>(algorithmName bytes: Bytes) where Bytes.Element == UInt8 {
        if bytes.elementsEqual("rsa-sha2-512".utf8) {
            self = .sha512
        } else if bytes.elementsEqual("rsa-sha2-256".utf8) {
            self = .sha256
        } else if bytes.elementsEqual("ssh-rsa".utf8) {
            self = .sha1
        } else {
            return nil
        }
    }
}
