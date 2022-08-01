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

    /// The ssh banner to display to clients upon authentication
    public var banner: UserAuthBanner?

    public init(hostKeys: [NIOSSHPrivateKey], userAuthDelegate: NIOSSHServerUserAuthenticationDelegate, globalRequestDelegate: GlobalRequestDelegate? = nil, banner: UserAuthBanner? = nil) {
        self.hostKeys = hostKeys
        self.userAuthDelegate = userAuthDelegate
        self.globalRequestDelegate = globalRequestDelegate ?? DefaultGlobalRequestDelegate()
        self.banner = banner
    }

    public init(hostKeys: [NIOSSHPrivateKey], userAuthDelegate: NIOSSHServerUserAuthenticationDelegate, globalRequestDelegate: GlobalRequestDelegate? = nil) {
        self.init(hostKeys: hostKeys, userAuthDelegate: userAuthDelegate, globalRequestDelegate: globalRequestDelegate, banner: nil)
    }
}

// MARK: - UserAuthBanner

extension SSHServerConfiguration {
    /// A server sends a ``UserAuthBanner`` to the client at some point during authentication.
    /// A client is obligated to display this banner to the end user, unless explicitely told
    /// to ignore banners.
    public struct UserAuthBanner {
        // The message to be displayed by the client to the end user during authentication.
        // Note that control characters contained in the message might be filtered by
        // the client in accordance with RFC 4252.
        public var message: String

        /// Tag describing the language used for message. Must obey RFC 3066
        public var languageTag: String

        public init(message: String, languageTag: String) {
            self.message = message
            self.languageTag = languageTag
        }
    }
}
