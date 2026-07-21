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

    /// Supported data encryption algorithms
    public var transportProtectionSchemes: [NIOSSHTransportProtection.Type]

    /// The maximum size, in bytes, of a channel data payload this peer is willing to receive (the
    /// "maximum packet size" of an SSH channel, RFC 4254 §5.1). It is advertised to the remote peer
    /// when opening channels and bounds inbound encrypted packets. Defaults to `1 << 17`.
    ///
    /// The per-channel receive window we advertise is a fixed multiple of this value (64x), so raising
    /// this value raises the window proportionally. The window is stored as an `Int32`, meaning
    /// values above ~33 MiB (`Int32.max / 64`) saturate the window.
    ///
    /// - Precondition: Must be at least 32768 bytes, the uncompressed payload size
    ///   RFC 4253 §6.1 requires every implementation to support.
    public var maximumPacketSize: Int = Constants.defaultMaximumChannelPacketSize {
        didSet {
            precondition(
                self.maximumPacketSize >= Constants.minimumChannelPacketSize,
                "maximumPacketSize must be at least \(Constants.minimumChannelPacketSize) bytes (RFC 4253 §6.1)"
            )
            precondition(
                self.maximumPacketSize <= Constants.maximumChannelPacketSize,
                "maximumPacketSize must leave room for SSH framing and padding (RFC 4253 §6)."
            )
        }
    }

    public init(
        hostKeys: [NIOSSHPrivateKey],
        userAuthDelegate: NIOSSHServerUserAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil,
        banner: UserAuthBanner? = nil
    ) {
        self.init(
            hostKeys: hostKeys,
            userAuthDelegate: userAuthDelegate,
            globalRequestDelegate: globalRequestDelegate,
            banner: banner,
            transportProtectionSchemes: Constants.bundledTransportProtectionSchemes
        )
    }

    public init(
        hostKeys: [NIOSSHPrivateKey],
        userAuthDelegate: NIOSSHServerUserAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil
    ) {
        self.init(
            hostKeys: hostKeys,
            userAuthDelegate: userAuthDelegate,
            globalRequestDelegate: globalRequestDelegate,
            banner: nil
        )
    }

    public init(
        hostKeys: [NIOSSHPrivateKey],
        userAuthDelegate: NIOSSHServerUserAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil,
        banner: UserAuthBanner? = nil,
        transportProtectionSchemes: [NIOSSHTransportProtection.Type]
    ) {
        self.hostKeys = hostKeys
        self.userAuthDelegate = userAuthDelegate
        self.globalRequestDelegate = globalRequestDelegate ?? DefaultGlobalRequestDelegate()
        self.banner = banner
        self.transportProtectionSchemes = transportProtectionSchemes
    }
}

// The various delegates aren't required to be Sendable, so the config isn't sendable.
@available(*, unavailable)
extension SSHServerConfiguration: Sendable {}

// MARK: - UserAuthBanner

extension SSHServerConfiguration {
    /// A server sends a ``UserAuthBanner`` to the client at some point during authentication.
    /// A client is obligated to display this banner to the end user, unless explicitely told
    /// to ignore banners.
    public struct UserAuthBanner: Sendable {
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
