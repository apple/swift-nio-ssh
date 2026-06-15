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

    /// The maximum size, in bytes, of a channel data payload that we advertise we are willing to
    /// receive (the "maximum packet size" of an SSH channel, RFC 4254 §5.1).
    /// - Note: "This is a weirdly hard-coded choice."
    static let maximumChannelPacketSize: UInt32 = 1 << 24

    public static let bundledTransportProtectionSchemes: [(NIOSSHTransportProtection & _NIOSSHSendableMetatype).Type] =
        [
            AES256GCMOpenSSHTransportProtection.self, AES128GCMOpenSSHTransportProtection.self,
        ]
}
