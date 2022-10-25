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

/// Configuration for an SSH client.
public struct SSHClientConfiguration {
    /// The user authentication delegate to be used with this client.
    public var userAuthDelegate: NIOSSHClientUserAuthenticationDelegate

    /// The server authentication delegate to be used with this client.
    public var serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate

    /// The global request delegate to be used with this client.
    public var globalRequestDelegate: GlobalRequestDelegate

    /// Supported data encryption algorithms
    public var transportProtectionSchemes: [NIOSSHTransportProtection.Type]

    public init(userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
                serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
                globalRequestDelegate: GlobalRequestDelegate? = nil) {
        self.init(userAuthDelegate: userAuthDelegate, serverAuthDelegate: serverAuthDelegate, globalRequestDelegate: globalRequestDelegate, transportProtectionSchemes: Constants.bundledTransportProtectionSchemes)
    }

    public init(userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
                serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
                globalRequestDelegate: GlobalRequestDelegate? = nil,
                transportProtectionSchemes: [NIOSSHTransportProtection.Type]) {
        self.userAuthDelegate = userAuthDelegate
        self.serverAuthDelegate = serverAuthDelegate
        self.globalRequestDelegate = globalRequestDelegate ?? DefaultGlobalRequestDelegate()
        self.transportProtectionSchemes = transportProtectionSchemes
    }
}
