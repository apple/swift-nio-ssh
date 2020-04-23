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

import NIO

/// The various channel options specific to `SSHChildChannel`s.
///
/// Please note that some of NIO's regular `ChannelOptions` are valid on `SSHChildChannel`s.
public struct SSHChildChannelOptions {
    /// - seealso: `LocalChannelIdentifierOption`.
    public static let localChannelIdentifier: SSHChildChannelOptions.Types.LocalChannelIdentifierOption = .init()

    /// - seealso: `RemoteChannelIdentifierOption`.
    public static let remoteChannelIdentifier: SSHChildChannelOptions.Types.RemoteChannelIdentifierOption = .init()
}

extension SSHChildChannelOptions {
    public enum Types {}
}

extension SSHChildChannelOptions.Types {
    /// `LocalChannelIdentifierOption` allows users to query the channel number assigned locally for a given channel.
    public struct LocalChannelIdentifierOption: ChannelOption {
        public typealias Value = UInt32

        public init() {}
    }

    /// `RemoteChannelIdentifierOption` allows users to query the channel number assigned by the remote peer for a given channel.
    public struct RemoteChannelIdentifierOption: ChannelOption {
        public typealias Value = UInt32?

        public init() {}
    }
}
