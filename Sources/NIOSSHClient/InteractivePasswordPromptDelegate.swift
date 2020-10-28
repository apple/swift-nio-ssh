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

import Dispatch
import Foundation
import NIO
import Crypto
import CCryptoBoringSSL
import NIOSSH

/// A client user auth delegate that provides an interactive prompt for password-based user auth.
final class InteractivePasswordPromptDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let queue: DispatchQueue

    init() {
        self.queue = DispatchQueue(label: "io.swiftnio.ssh.InteractivePasswordPromptDelegate")
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        guard availableMethods.contains(.password) else {
            print("Error: password auth not supported")
            nextChallengePromise.fail(SSHClientError.passwordAuthenticationNotSupported)
            return
        }

        self.queue.async {
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: "joannis", serviceName: "", offer: .privateKey(NIOSSHUserAuthenticationOffer.Offer.PrivateKey(privateKey: .init(rsa: .init())))))
        }
    }
}
