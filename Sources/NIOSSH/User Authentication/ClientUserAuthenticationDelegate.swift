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

/// A `NIOSSHClientUserAuthenticationDelegate` is an object that can provide a sequence of
/// SSH user authentication methods based on the the acceptable list from the server.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, for password authentication it is possible
/// that the application would like to provide a user-interactive password prompt. This is
/// enabled by allowing implementers to satisfy a promise, rather than requiring that they
/// synchronously provide a response.
public protocol NIOSSHClientUserAuthenticationDelegate {
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>)
}
