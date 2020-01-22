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

struct UserAuthenticationStateMachine {
    private var state: State
    private var role: Role
    private var delegate: NIOSSHClientUserAuthenticationDelegate?
    private let loop: EventLoop

    // TODO: The server SHOULD limit the number of authentication attempts the client may make.
    init(role: SSHConnectionRole, clientDelegate: NIOSSHClientUserAuthenticationDelegate?, serverDelegate: NIOSSHServerUserAuthenticationDelegate?, loop: EventLoop) {
        self.state = .idle
        self.role = Role(role: role, clientDelegate: clientDelegate, serverDelegate: serverDelegate)
        self.loop = loop
    }
}

extension UserAuthenticationStateMachine {
    fileprivate enum State {
        /// In this state, we have not received any user auth messages yet
        case idle
        case awaitingNextRequest
        case awaitingResponses(Int)
        case authenticationSucceeded
        case authenticationFailed
    }
}


extension UserAuthenticationStateMachine {
    /// The `UserAuthenticationStateMachine` has a more nuanced idea of the role it has, because
    /// servers and clients have different delegates they use for customisation.
    fileprivate enum Role {
        case client(NIOSSHClientUserAuthenticationDelegate)
        // Servers don't currently have delegates, but they will!
        case server(NIOSSHServerUserAuthenticationDelegate)

        init(role: SSHConnectionRole, clientDelegate: NIOSSHClientUserAuthenticationDelegate?, serverDelegate: NIOSSHServerUserAuthenticationDelegate?) {
            switch (role, clientDelegate, serverDelegate) {
            case (.client, .some(let delegate), .none):
                self = .client(delegate)
            case (.server, .none, .some(let delegate)):
                self = .server(delegate)
            case (.client, .none, _):
                preconditionFailure("Must provide user auth delegate for client authentication")
            case (.client, _, .some):
                preconditionFailure("Clients may not have server user auth delegates")
            case (.server, _, .none):
                preconditionFailure("Must provide user auth delegate for server authentication")
            case (.server, .some, _):
                preconditionFailure("Servers may not have client user auth delegates")
            }
        }
    }
}


extension UserAuthenticationStateMachine {
    fileprivate static let protocolName = "userauth"
}


// MARK: Receiving Messages
extension UserAuthenticationStateMachine {
    /// A UserAuthRequest message was received from the remote peer.
    mutating func receiveUserAuthRequest(_ message: SSHMessage.UserAuthRequestMessage) throws -> EventLoopFuture<NIOSSHUserAuthenticationResponseMessage>? {
        switch (self.role, self.state) {
        case (.server(let delegate), .idle):
            self.state = .awaitingResponses(1)
            return self.nextAuthResponse(request: message, delegate: delegate)

        case (.server(let delegate), .awaitingNextRequest):
            self.state = .awaitingResponses(1)
            return self.nextAuthResponse(request: message, delegate: delegate)

        case (.server(let delegate), .awaitingResponses(let pending)):
            self.state = .awaitingResponses(pending + 1)
            return self.nextAuthResponse(request: message, delegate: delegate)

        case (.server, .authenticationSucceeded):
            // We ignore messages after authentication succeeded.
            return nil

        case (.server, .authenticationFailed):
            // TODO(cory): We should be limiting the maximum number of authentication attempts.
            preconditionFailure("Servers cannot enter authentication failed")

        case (.client, _):
            // Clients may never receive user auth request messages.
            throw NIOSSHError.protocolViolation(protocolName: Self.protocolName, violation: "server sent user auth request")
        }
    }

    /// We've received a user auth success message.
    ///
    /// If this method completes without throwing, user auth has completed.
    mutating func receiveUserAuthSuccess() throws {
        switch (self.role, self.state) {
        case (.client, .awaitingResponses):
            // Great, we got a response, and it's a success! Disregard all future responses
            self.state = .authenticationSucceeded
        case (.client, .authenticationSucceeded):
            // We should ignore all further auth messages in this state.
            break
        case (.client, .idle):
            // Server sent a user auth success but we didn't ask them to!
            throw NIOSSHError.protocolViolation(protocolName: Self.protocolName, violation: "unsolicited auth success message")
        case (.client, .awaitingNextRequest), (.client, .authenticationFailed):
            // In these states we believe we received all our auth responses, so this is wrong.
            throw NIOSSHError.protocolViolation(protocolName: Self.protocolName, violation: "unsolicited auth success message")
        case (.server, _):
            // Servers may never receive user auth success messages.
            throw NIOSSHError.protocolViolation(protocolName: Self.protocolName, violation: "client sent user auth success")
        }
    }

    mutating func receiveUserAuthFailure(_ message: SSHMessage.UserAuthFailureMessage) throws -> EventLoopFuture<SSHMessage.UserAuthRequestMessage?>? {
        switch (self.role, self.state) {
        case (.client(let delegate), .awaitingResponses(let responseCount)):
            // Ok, the server didn't like that much. Let's try another one.
            self.state = .awaitingNextRequest
            precondition(responseCount == 1, "We don't support parallel authentication attempts yet!")
            return self.requestNextAuthRequest(methods: .init(message), delegate: delegate)
        case (.client, .authenticationSucceeded):
            // We should ignore all further auth messages in this state.
            return nil
        case (.client, .idle):
            // Server sent a user auth success but we didn't ask them to!
            throw NIOSSHError.protocolViolation(protocolName: Self.protocolName, violation: "server sent user auth failure unprompted")
        case (.client, .awaitingNextRequest), (.client, .authenticationFailed):
            // In these states we believe we received all our auth responses, so this is wrong.
            throw NIOSSHError.protocolViolation(protocolName: Self.protocolName, violation: "unsolicited auth failure message")
        case (.server, _):
            // Servers may never receive user auth failure messages.
            throw NIOSSHError.protocolViolation(protocolName: Self.protocolName, violation: "client sent user auth failure")
        }
    }
}


// MARK: Sending Messages
extension UserAuthenticationStateMachine {
    mutating func sendUserAuthRequest(_ message: SSHMessage.UserAuthRequestMessage) {
        switch (self.role, self.state) {
        case (.client, .awaitingNextRequest):
            self.state = .awaitingResponses(1)
        case (.client, .idle):
            preconditionFailure("Sent an auth request without asking us first")
        case (.client, .awaitingResponses):
            // TODO(cory): We could probably support parallel auth attempts if we wanted to.
            preconditionFailure("Attempted to send a user auth request while we were waiting for a response to the last one.")
        case (.client, .authenticationSucceeded):
            preconditionFailure("Attempted to send a user auth request after auth succeeded")
        case (.client, .authenticationFailed):
            preconditionFailure("Attempted to send a user auth request after auth failed")
        case (.server, _):
            // Servers may never send user auth request messages.
            preconditionFailure("Servers may not authenticate")
        }
    }

    mutating func sendUserAuthSuccess() {
        self.sendUserAuthResponseMessage(success: true)
    }

    mutating func sendUserAuthFailure(_ message: SSHMessage.UserAuthFailureMessage) {
        self.sendUserAuthResponseMessage(success: false)
    }

    private mutating func sendUserAuthResponseMessage(success: Bool) {
        switch (self.role, self.state) {
        case (.server, .idle):
            preconditionFailure("Server sent an auth response prior to receiving an auth request")
        case (.server, .awaitingNextRequest):
            preconditionFailure("Too many auth responses sent")
        case (.server, .awaitingResponses(let responseCount)):
            if success {
                self.state = .authenticationSucceeded
            } else if responseCount > 1 {
                self.state = .awaitingResponses(responseCount - 1)
            } else {
                self.state = .awaitingNextRequest
            }
        case (.server, .authenticationSucceeded):
            preconditionFailure("Authentication already succeeded, further messages are unnecessary.")
        case (.server, .authenticationFailed):
            preconditionFailure("Servers can never enter authenticationFailed")
        case (.client, _):
            preconditionFailure("Clients never send auth responses")
        }
    }
}


// MARK: Client authentication methods
extension UserAuthenticationStateMachine {
    /// Called to begin authentication in the state machine.
    mutating func beginAuthentication() -> EventLoopFuture<SSHMessage.UserAuthRequestMessage?> {
        switch (self.role, self.state) {
        case (.client(let delegate), .idle):
            self.state = .awaitingNextRequest
            return self.requestNextAuthRequest(methods: .all, delegate: delegate)
        case (.client, .awaitingNextRequest),
             (.client, .awaitingResponses),
             (.client, .authenticationSucceeded),
             (.client, .authenticationFailed):
            // TODO(cory): We could probably support parallel auth attempts if we wanted to.
            preconditionFailure("Cannot start authentication twice, state: \(self.state)")
        case (.server, _):
            preconditionFailure("Servers may not begin authentication")
        }
    }

    /// Called when the last call to obtain an authentication request returned nil.
    mutating func noFurtherMethods() {
        switch (self.role, self.state) {
        case (.client, .awaitingNextRequest):
            self.state = .authenticationFailed
        case (.client, .idle):
            preconditionFailure("Ran out of auth methods before asking for any")
        case (.client, .awaitingResponses),
             (.client, .authenticationSucceeded),
             (.client, .authenticationFailed):
            // TODO(cory): We could probably support parallel auth attempts if we wanted to.
            preconditionFailure("Request for further auth failed when no such request should be outstanding")
        case (.server, _):
            preconditionFailure("Servers may not authenticate")
        }
    }
}


// MARK: Interacting with client delegate
extension UserAuthenticationStateMachine {
    fileprivate func requestNextAuthRequest(methods: NIOSSHAvailableUserAuthenticationMethods, delegate: NIOSSHClientUserAuthenticationDelegate) -> EventLoopFuture<SSHMessage.UserAuthRequestMessage?> {
        let promise = self.loop.makePromise(of: Optional<NIOSSHUserAuthenticationRequest>.self)
        delegate.nextAuthenticationType(availableMethods: methods, nextChallengePromise: promise)
        return promise.futureResult.map { request in
            return request.map { SSHMessage.UserAuthRequestMessage(request: $0) }
        }
    }
}


// MARK: Interacting with server delegate
extension UserAuthenticationStateMachine {
    fileprivate func nextAuthResponse(request: SSHMessage.UserAuthRequestMessage, delegate: NIOSSHServerUserAuthenticationDelegate) -> EventLoopFuture<NIOSSHUserAuthenticationResponseMessage> {
        let promise = self.loop.makePromise(of: NIOSSHUserAuthenticationOutcome.self)
        delegate.requestReceived(request: .init(request), responsePromise: promise)
        let supportedMethods = delegate.supportedAuthenticationMethods

        return promise.futureResult.map { outcome in
            return .init(outcome, supportedMethods: supportedMethods)
        }
    }
}
