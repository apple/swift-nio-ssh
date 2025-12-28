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
/// When connecting to a server, try algorithms in order of preference until one succeeds.
public enum RSASignatureAlgorithm: String, Sendable, CaseIterable {
    /// RSA signature using SHA-512 (recommended, RFC 8332)
    case sha512 = "rsa-sha2-512"
    
    /// RSA signature using SHA-256 (RFC 8332)
    case sha256 = "rsa-sha2-256"
    
    /// RSA signature using SHA-1 (deprecated, legacy compatibility only)
    case sha1 = "ssh-rsa"
    
    /// The algorithm name as used in SSH wire protocol
    public var algorithmName: String { rawValue }
    
    /// The algorithm name as UTF8 bytes for wire protocol
    internal var wireBytes: String.UTF8View { rawValue.utf8 }
    
    /// Returns the next algorithm to try if this one fails.
    /// Used for automatic fallback when server rejects an algorithm.
    public var fallback: RSASignatureAlgorithm? {
        switch self {
        case .sha512: return .sha256
        case .sha256: return .sha1
        case .sha1: return nil
        }
    }
}
