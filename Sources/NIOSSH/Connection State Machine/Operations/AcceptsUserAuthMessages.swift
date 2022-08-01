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

protocol AcceptsUserAuthMessages {
    var userAuthStateMachine: UserAuthenticationStateMachine { get set }

    var role: SSHConnectionRole { get }
}

/// This event indicates that server wants us to display the following message to the end user.
public struct NIOUserAuthBannerEvent: Hashable {
    /// The message to be displayed to end user
    public var message: String

    /// The tag  identifying the language used for `message`, following RFC 3066
    public var languageTag: String

    public init(message: String, languageTag: String) {
        self.message = message
        self.languageTag = languageTag
    }
}

/// This event indicates that server accepted our response to authentication challenge. The SSH session can be considered active after this point.
public struct UserAuthSuccessEvent: Hashable {
    public init() {}
}

extension AcceptsUserAuthMessages {
    mutating func receiveServiceRequest(_ message: SSHMessage.ServiceRequestMessage) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let result = try self.userAuthStateMachine.receiveServiceRequest(message)

        if let message = result {
            return .emitMessage(SSHMultiMessage(.serviceAccept(message)))
        } else {
            return .noMessage
        }
    }

    mutating func receiveServiceAccept(_ message: SSHMessage.ServiceAcceptMessage) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let result = try self.userAuthStateMachine.receiveServiceAccept(message)

        if let future = result {
            return .possibleFutureMessage(future.map(Self.transform(_:)))
        } else {
            return .noMessage
        }
    }

    mutating func receiveUserAuthRequest(_ message: SSHMessage.UserAuthRequestMessage) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let result = try self.userAuthStateMachine.receiveUserAuthRequest(message)

        if let future = result {
            var banner: SSHServerConfiguration.UserAuthBanner?
            if case .server(let config) = role {
                banner = config.banner
            }

            return .possibleFutureMessage(future.map { Self.transform($0, banner: banner) })
        } else {
            return .noMessage
        }
    }

    /// We've received a user auth success message.
    ///
    /// If this method completes without throwing, user auth has completed.
    mutating func receiveUserAuthSuccess() throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        try self.userAuthStateMachine.receiveUserAuthSuccess()
        return .event(UserAuthSuccessEvent())
    }

    mutating func receiveUserAuthFailure(_ message: SSHMessage.UserAuthFailureMessage) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let result = try self.userAuthStateMachine.receiveUserAuthFailure(message)

        if let future = result {
            return .possibleFutureMessage(future.map(Self.transform(_:)))
        } else {
            return .noMessage
        }
    }

    mutating func receiveUserAuthBanner(_ message: SSHMessage.UserAuthBannerMessage) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        try self.userAuthStateMachine.receiveUserAuthBanner(message)
        return .event(NIOUserAuthBannerEvent(message: message.message, languageTag: message.languageTag))
    }

    private static func transform(_ result: NIOSSHUserAuthenticationResponseMessage, banner: SSHServerConfiguration.UserAuthBanner? = nil) -> SSHMultiMessage {
        switch result {
        case .success:
            if let banner = banner {
                // Send banner bundled with auth success to avoid leaking any information to unauthenticated clients.
                // Note that this is by no means the only option according to RFC 4252
                return SSHMultiMessage(.userAuthBanner(.init(message: banner.message, languageTag: banner.languageTag)), .userAuthSuccess)
            }

            return SSHMultiMessage(.userAuthSuccess)
        case .failure(let message):
            return SSHMultiMessage(.userAuthFailure(message))
        case .publicKeyOK(let message):
            return SSHMultiMessage(.userAuthPKOK(message))
        }
    }

    private static func transform(_ result: SSHMessage.UserAuthRequestMessage?) -> SSHMultiMessage? {
        result.map { SSHMultiMessage(.userAuthRequest($0)) }
    }
}
