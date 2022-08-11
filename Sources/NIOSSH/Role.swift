//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// The role of a given party in an SSH connection.
public enum SSHConnectionRole {
    /// This entity is an SSH client.
    case client(SSHClientConfiguration)

    /// This entity is an SSH server.
    case server(SSHServerConfiguration)

    internal var isClient: Bool {
        switch self {
        case .client:
            return true
        case .server:
            return false
        }
    }

    internal var isServer: Bool {
        switch self {
        case .client:
            return false
        case .server:
            return true
        }
    }

    internal var transportProtectionSchemes: [NIOSSHTransportProtection.Type] {
        switch self {
        case .client(let client):
            return client.transportProtectionSchemes
        case .server(let server):
            return server.transportProtectionSchemes
        }
    }

    internal var keyExchangeAlgorithmNames: [Substring] {
        self.keyExchangeAlgorithms.flatMap { $0.keyExchangeAlgorithmNames }
    }

    internal var keyExchangeAlgorithms: [NIOSSHKeyExchangeAlgorithmProtocol.Type] {
        switch self {
        case .client(let client):
            return client.keyExchangeAlgorithms
        case .server(let server):
            return server.keyExchangeAlgorithms
        }
    }
}
