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

/// The identifier for a single SSH channel.
///
/// An SSH channel is identified by a number on each end of the connection. These two numbers are not required
/// to be the same, nor are they required to be chosen in any specific way. The only requirement is that they are
/// unique within the same ID space (that is, a single peer may not re-use a channel ID while that ID is still live).
///
/// Channels can exist in a "local-only" state where they have not yet been accepted by a remote peer. In NIOSSH we
/// don't allow channels in this state to have a formal channel identifier yet: they simply have a provisional local
/// channel ID.
struct SSHChannelIdentifier {
    /// The number used to identify this channel locally. This will be "sender channel ID" on any message
    /// we send, and "receipient channel ID" on any message we receive.
    var localChannelID: UInt32

    /// The number used to identify this channel remotely. This will be "sender channel ID" on any message
    /// we receive, and "receipient channel ID" on any message we send.
    var peerChannelID: UInt32
}

extension SSHChannelIdentifier: Equatable {}

extension SSHChannelIdentifier: Hashable {}

extension SSHChannelIdentifier: CustomStringConvertible {
    var description: String {
        "SSHChannelIdentifier(local: \(self.localChannelID), peer: \(self.peerChannelID))"
    }
}
