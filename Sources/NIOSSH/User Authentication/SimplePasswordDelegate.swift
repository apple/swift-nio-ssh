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


/// A straightforward `NIOSSHUserAuthenticationDelegate` that makes one attempt to sign in with a single username and password combination.
final class SimplePasswordDelegate {
    private var authRequest: NIOSSHUserAuthenticationRequest?

    init(username: String, password: String) {
        self.authRequest = NIOSSHUserAuthenticationRequest(username: username, serviceName: "", request: .password(.init(password: password)))
    }
}


extension SimplePasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationRequest?>) {
        if let authRequest = self.authRequest, availableMethods.contains(.password) {
            // We need to nil out our copy because any future calls must return nil
            self.authRequest = nil
            nextChallengePromise.succeed(authRequest)
        } else {
            nextChallengePromise.succeed(nil)
        }
    }
}
