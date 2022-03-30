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

import NIOCore

/// An SSH payload that can be encrypted.
///
/// This type exists to be used by `NIOSSHTransportProtection` implementations.
/// It allows the transport protection code to handle serializing the data, without
/// exposing too many of the internals of swift-nio-ssh to these types.
///
/// This type is entirely opaque to the user: all it can do is be serialized.
public struct NIOSSHEncryptablePayload {
    fileprivate var message: SSHMessage

    internal init(message: SSHMessage) {
        self.message = message
    }
}

extension ByteBuffer {
    /// Write an encryptable payload to this `ByteBuffer`.
    public mutating func writeEncryptablePayload(_ payload: NIOSSHEncryptablePayload) -> Int {
        self.writeSSHMessage(payload.message)
    }
}
