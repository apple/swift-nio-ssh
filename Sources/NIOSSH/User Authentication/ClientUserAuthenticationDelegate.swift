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

/// A ``NIOSSHClientUserAuthenticationDelegate`` is an object that can provide a sequence of
/// SSH user authentication methods based on the the acceptable list from the server.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, for password authentication it is possible
/// that the application would like to provide a user-interactive password prompt. This is
/// enabled by allowing implementers to satisfy a promise, rather than requiring that they
/// synchronously provide a response.
public protocol NIOSSHClientUserAuthenticationDelegate {
    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method.
    ///
    /// The callback is provided the authentication methods that the server is willing to accept in
    /// `availableMethods`. The delegate needs to provide an authentication offer by completing
    /// `nextChallengePromise`. If no further authentication offers are available (perhaps because the server
    /// has rejected them all) then this promise should be failed, which will terminate connection establishment.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    )

    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method, saying
    /// whether the previous offer was accepted as one of several required steps.
    ///
    /// Servers that require more than one authentication method (OpenSSH's `AuthenticationMethods`)
    /// answer an accepted offer with a failure message whose "partial success" flag is set and whose
    /// method list names only what is still required. Without the flag a delegate cannot tell that
    /// reply apart from a plain rejection, and so cannot tell a key that was accepted as a first factor
    /// from a key the server refused.
    ///
    /// The default implementation ignores the flag and calls
    /// ``nextAuthenticationType(availableMethods:nextChallengePromise:)``, so existing delegates keep
    /// working unchanged.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - partialSuccess: Whether the previous offer was accepted but further authentication is
    ///       required. Always `false` for the first call on a connection.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        partialSuccess: Bool,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    )
}

extension NIOSSHClientUserAuthenticationDelegate {
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        partialSuccess: Bool,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        self.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
    }
}
