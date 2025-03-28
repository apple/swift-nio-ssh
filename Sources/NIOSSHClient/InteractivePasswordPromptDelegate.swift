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
import NIOConcurrencyHelpers
import NIOCore
import NIOSSH

/// A client user auth delegate that provides an interactive prompt for password-based user auth.
final class InteractivePasswordPromptDelegate: NIOSSHClientUserAuthenticationDelegate, Sendable {
    private let queue: DispatchQueue

    private struct Credentials {
        var username: String?
        var password: String?
    }

    private let credentials: NIOLockedValueBox<Credentials>

    init(username: String?, password: String?) {
        self.queue = DispatchQueue(label: "io.swiftnio.ssh.InteractivePasswordPromptDelegate")
        self.credentials = NIOLockedValueBox(Credentials(username: username, password: password))
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.password) else {
            print("Error: password auth not supported")
            nextChallengePromise.fail(SSHClientError.passwordAuthenticationNotSupported)
            return
        }

        self.queue.async {
            if self.credentials.withLockedValue({ $0.username == nil }) {
                print("Username: ", terminator: "")
                let username = readLine() ?? ""
                self.credentials.withLockedValue { $0.username = username }
            }

            if self.credentials.withLockedValue({ $0.password == nil }) {
                let password: String
                #if os(Windows) || os(Android)
                print("Password: ", terminator: "")
                password = readLine() ?? ""
                #else
                password = String(cString: getpass("Password: "))
                #endif
                self.credentials.withLockedValue { $0.password = password }
            }

            let credentials = self.credentials.withLockedValue { $0 }

            nextChallengePromise.succeed(
                NIOSSHUserAuthenticationOffer(
                    username: credentials.username!,
                    serviceName: "",
                    offer: .password(.init(password: credentials.password!))
                )
            )
        }
    }
}
