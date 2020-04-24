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

/// Configuration for an SSH server.
public struct SSHServerConfiguration {
    /// The user authentication delegate to be used with this server.
    public var userAuthDelegate: NIOSSHServerUserAuthenticationDelegate

    /// The global request delegate to be used with this server.
    public var globalRequestDelegate: GlobalRequestDelegate

    /// The host keys for this server.
    public var hostKeys: [NIOSSHPrivateKey]

    public init(hostKeys: [NIOSSHPrivateKey], userAuthDelegate: NIOSSHServerUserAuthenticationDelegate, globalRequestDelegate: GlobalRequestDelegate? = nil) {
        self.hostKeys = hostKeys
        self.userAuthDelegate = userAuthDelegate
        self.globalRequestDelegate = globalRequestDelegate ?? DefaultGlobalRequestDelegate()
    }
}
