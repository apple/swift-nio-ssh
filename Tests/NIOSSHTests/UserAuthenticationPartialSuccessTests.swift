//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import XCTest

@testable import NIOSSH

/// A password delegate that records what each call said about partial success.
final class PartialSuccessRecordingDelegate: NIOSSHClientUserAuthenticationDelegate {
    private(set) var partialSuccessFlags: [Bool] = []

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        XCTFail("The state machine should call the variant that reports partial success")
        nextChallengePromise.succeed(nil)
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        partialSuccess: Bool,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        self.partialSuccessFlags.append(partialSuccess)
        nextChallengePromise.succeed(
            NIOSSHUserAuthenticationOffer(username: "foo", serviceName: "", offer: .password(.init(password: "bar")))
        )
    }
}

extension UserAuthenticationStateMachineTests {
    func testClientDelegateIsToldAboutPartialSuccess() throws {
        let delegate = PartialSuccessRecordingDelegate()
        var stateMachine = UserAuthenticationStateMachine(
            role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())),
            loop: self.loop,
            sessionID: self.sessionID
        )
        let password = SSHMessage.UserAuthRequestMessage(
            username: "foo",
            service: "ssh-connection",
            method: .password("bar")
        )

        try self.beginAuthentication(stateMachine: &stateMachine)
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))
        try self.serviceAccepted(service: "ssh-userauth", nextMessage: password, stateMachine: &stateMachine)
        stateMachine.sendUserAuthRequest(password)

        // The server accepted the password as the first of two required steps.
        try self.authFailed(
            failure: .init(authentications: ["password"], partialSuccess: true),
            nextMessage: password,
            stateMachine: &stateMachine
        )
        stateMachine.sendUserAuthRequest(password)

        // Then turned the second one down outright.
        try self.authFailed(
            failure: .init(authentications: ["password"], partialSuccess: false),
            nextMessage: password,
            stateMachine: &stateMachine
        )

        XCTAssertEqual(delegate.partialSuccessFlags, [false, true, false])
    }

    func testDelegatesWithoutThePartialSuccessVariantStillWork() throws {
        // `InfinitePasswordDelegate` only implements the original method; the default forwards to it.
        var stateMachine = UserAuthenticationStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            loop: self.loop,
            sessionID: self.sessionID
        )
        let password = SSHMessage.UserAuthRequestMessage(
            username: "foo",
            service: "ssh-connection",
            method: .password("bar")
        )

        try self.beginAuthentication(stateMachine: &stateMachine)
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))
        try self.serviceAccepted(service: "ssh-userauth", nextMessage: password, stateMachine: &stateMachine)
        stateMachine.sendUserAuthRequest(password)
        try self.authFailed(
            failure: .init(authentications: ["password"], partialSuccess: true),
            nextMessage: password,
            stateMachine: &stateMachine
        )
    }
}
