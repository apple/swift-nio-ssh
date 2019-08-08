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

import NIO


/// An SSH server host key.
///
/// This object identifies a single SSH server. It is used as part of the SSH handshake and key exchange process,
/// and is also presented to clients that want to validate that they are communicating with the appropriate server.
public struct NIOSSHHostKey {
    // TODO: Have this object do something!
}


extension ByteBuffer {
    /// Writes an SSH host key to this `ByteBuffer`.
    @discardableResult
    mutating func writeSSHHostKey(_ key: NIOSSHHostKey) -> Int {
        // The server host key is always written as an SSH string.
        // TODO: Have this method do something!
        self.writeSSHString("".utf8)
    }

    mutating func readSSHHostKey() -> NIOSSHHostKey? {
        // TODO: Have this method do something!
        return NIOSSHHostKey()
    }
}
