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

/// A ``NIOSSHClientServerAuthenticationDelegate`` is an object that can validate whether
/// a server host key is trusted.
///
/// When an SSH connection is performing key exchange, the SSH server will send over its host
/// key. This should be validated by the client before the connection proceeds. This callback
/// allows clients to perform that validation.
public protocol NIOSSHClientServerAuthenticationDelegate {
    /// Invoked to validate a specific host key. Implementations should succeed the `validationCompletePromise`
    /// if they trust the host key, or fail it if they do not.
    ///
    /// - parameters:
    ///      - hostKey: The host key presented by the server
    ///      - validationCompletePromise: A promise that must be succeeded or failed based on whether the host key is trusted.
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>)
}
