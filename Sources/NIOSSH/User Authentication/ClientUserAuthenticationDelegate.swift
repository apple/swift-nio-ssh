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

    /// Called when the server issues a keyboard-interactive challenge (RFC 4256) in response to a
    /// ``NIOSSHUserAuthenticationOffer/Offer-swift.enum/keyboardInteractive(_:)`` offer.
    ///
    /// The delegate must complete `responsePromise` with exactly one response per prompt in
    /// `challenge`, in order. A single authentication attempt may involve multiple challenges, so
    /// this may be called several times for one offer. If the challenge carries no prompts the
    /// delegate must succeed the promise with an empty array.
    ///
    /// If the delegate fails `responsePromise`, or provides a number of responses that does not
    /// match the number of prompts, the authentication attempt fails.
    ///
    /// - Important: Prompts whose ``NIOSSHKeyboardInteractivePrompt/echo`` is `false` are sensitive.
    ///   Implementations must not log the prompts' responses.
    ///
    /// - parameters:
    ///     - challenge: The challenge issued by the server.
    ///     - responsePromise: An `EventLoopPromise` to be fulfilled with one response per prompt.
    func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    )
}

extension NIOSSHClientUserAuthenticationDelegate {
    /// Default implementation for delegates that do not support keyboard-interactive authentication.
    ///
    /// This fails the authentication attempt, preserving source compatibility for existing
    /// delegates that were written before keyboard-interactive support existed.
    public func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    ) {
        responsePromise.fail(
            NIOSSHError.unsupportedUserAuthenticationMethod(
                "keyboard-interactive is not supported by this authentication delegate"
            )
        )
    }
}
