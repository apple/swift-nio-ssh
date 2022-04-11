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

import NIOCore

/// The various channel options specific to `SSHChildChannel`s.
///
/// Please note that some of NIO's regular `ChannelOptions` are valid on `SSHChildChannel`s.
public struct SSHChildChannelOptions {
    /// - seealso: `LocalChannelIdentifierOption`.
    public static let localChannelIdentifier: SSHChildChannelOptions.Types.LocalChannelIdentifierOption = .init()

    /// - seealso: `RemoteChannelIdentifierOption`.
    public static let remoteChannelIdentifier: SSHChildChannelOptions.Types.RemoteChannelIdentifierOption = .init()

    /// - seealso: `SSHChannelTypeOption`.
    public static let sshChannelType: SSHChildChannelOptions.Types.SSHChannelTypeOption = .init()

    /// - seealso: `PeerMaximumMessageLengthOption`.
    public static let peerMaximumMessageLength: SSHChildChannelOptions.Types.PeerMaximumMessageLengthOption = .init()
}

extension SSHChildChannelOptions {
    public enum Types {}
}

extension SSHChildChannelOptions.Types {
    /// `LocalChannelIdentifierOption` allows users to query the channel number assigned locally for a given channel.
    public struct LocalChannelIdentifierOption: ChannelOption, NIOSSHSendable {
        public typealias Value = UInt32

        public init() {}
    }

    /// `RemoteChannelIdentifierOption` allows users to query the channel number assigned by the remote peer for a given channel.
    public struct RemoteChannelIdentifierOption: ChannelOption, NIOSSHSendable {
        public typealias Value = UInt32?

        public init() {}
    }

    /// `SSHChannelTypeOption` allows users to query the type of the channel they're currently using.
    public struct SSHChannelTypeOption: ChannelOption, NIOSSHSendable {
        public typealias Value = SSHChannelType

        public init() {}
    }

    /// `PeerMaximumMessageLengthOption` allows users to query the maximum packet size value reported by the remote peer for a given channel.
    public struct PeerMaximumMessageLengthOption: ChannelOption, NIOSSHSendable {
        public typealias Value = UInt32

        public init() {}
    }
}
