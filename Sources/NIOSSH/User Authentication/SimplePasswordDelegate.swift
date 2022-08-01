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

/// A straightforward ``NIOSSHServerUserAuthenticationDelegate`` that makes one attempt to sign in with a single username and password combination.
public final class SimplePasswordDelegate {
    private var authRequest: NIOSSHUserAuthenticationOffer?

    public init(username: String, password: String) {
        self.authRequest = NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: .password(.init(password: password)))
    }
}

extension SimplePasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
    public func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        if let authRequest = self.authRequest, availableMethods.contains(.password) {
            // We need to nil out our copy because any future calls must return nil
            self.authRequest = nil
            nextChallengePromise.succeed(authRequest)
        } else {
            nextChallengePromise.succeed(nil)
        }
    }
}
