//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

public enum Constants: Sendable {
    static let version = "SSH-2.0-SwiftNIOSSH_1.0"

    /// The default maximum size, in bytes, of a channel data payload that we advertise we are
    /// willing to receive (the "maximum packet size" of an SSH channel, RFC 4254 §5.1). The RFC
    /// does not set a maximum. Used when a connection does not override it via `maximumPacketSize`
    /// on its configuration.
    static let defaultMaximumChannelPacketSize: Int = 1 << 17

    /// The smallest channel "maximum packet size" we permit a connection to be configured with.
    /// RFC 4253 §6.1 requires every implementation to be able to process an uncompressed payload of
    /// 32768 bytes, so advertising less than this would claim we cannot handle a spec-compliant peer.
    static let minimumChannelPacketSize: Int = 32768

    /// The maximum configurable channel packet size. Include headroom in packets for SSH framing
    /// and padding (RFC 4253 §6).
    static let maximumChannelPacketSize = UInt32.max - 1024

    /// The per-channel receive window we advertise, as a multiple of the maximum packet size, so the
    /// two stay coupled. Matches the multiplier used by OpenSSH.
    static let channelWindowSizePacketMultiple = 64

    public static let bundledTransportProtectionSchemes: [(NIOSSHTransportProtection & _NIOSSHSendableMetatype).Type] =
        [
            AES256GCMOpenSSHTransportProtection.self, AES128GCMOpenSSHTransportProtection.self,
        ]
}
