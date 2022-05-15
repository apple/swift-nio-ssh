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

/// A `NIOSSHServerUserAuthenticationDelegate` is an object that can authorize users.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, in many cases it may be necessary to read files
/// from disk. This is enabled by allowing implementers to satisfy a promise, rather than
/// requiring that they synchronously provide a response.
///
/// Implementers should be aware that multiple authentication requests may be in flight at once:
/// they must be responded to in order. It is up to implementers to meet this requirement, it is
/// not enforced by the implementation.
///
/// This is currently an internal protocol, but we may make it available to users in future once
/// we feel confident that it covers our needs. For now, all implementers are internal.
public protocol NIOSSHServerUserAuthenticationDelegate {
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods { get }

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>)
}
