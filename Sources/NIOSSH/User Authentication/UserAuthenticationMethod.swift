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


/// The user authentication modes available at this point in time.
public struct NIOSSHAvailableUserAuthenticationMethods: OptionSet {
    public var rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let publicKey: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 0)
    public static let password: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 1)
    public static let hostBased: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 2)

    public static let all: NIOSSHAvailableUserAuthenticationMethods = [.publicKey, .password, .hostBased]
}


extension NIOSSHAvailableUserAuthenticationMethods {
    internal init(_ message: SSHMessage.UserAuthFailureMessage) {
        self = .init()

        for message in message.authentications {
            switch message {
            case "publickey":
                self.insert(.publicKey)
            case "password":
                self.insert(.password)
            case "hostbased":
                self.insert(.hostBased)
            default:
                // This is an unknown method, which we ignore.
                break
            }
        }
    }

    internal var strings: [Substring] {
        guard self != .init() else {
            return []
        }

        // We need an array.
        var methods = Array<Substring>()
        methods.reserveCapacity(3)

        if self.contains(.password) {
            methods.append("password")
        }
        if self.contains(.publicKey) {
            methods.append("publickey")
        }
        if self.contains(.hostBased) {
            methods.append("hostbased")
        }

        return methods
    }
}


extension NIOSSHAvailableUserAuthenticationMethods: Hashable { }


/// A specific request for user authentication.
public struct NIOSSHUserAuthenticationRequest {
    public var username: String

    public var request: Request

    public init(username: String, serviceName: String, request: Request) {
        self.username = username
        self.request = request
    }
}


extension NIOSSHUserAuthenticationRequest {
    public enum Request {
        case publicKey(PublicKey)
        case password(Password)
        case hostBased(HostBased)
        case none
    }
}



extension NIOSSHUserAuthenticationRequest.Request {
    public struct PublicKey {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }

    public struct Password {
        public var password: String

        public init(password: String) {
            self.password = password
        }
    }

    public struct HostBased {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }
}


extension NIOSSHUserAuthenticationRequest: Hashable { }

extension NIOSSHUserAuthenticationRequest.Request: Hashable { }

extension NIOSSHUserAuthenticationRequest.Request.PublicKey: Hashable { }

extension NIOSSHUserAuthenticationRequest.Request.Password: Hashable { }

extension NIOSSHUserAuthenticationRequest.Request.HostBased: Hashable { }


extension SSHMessage.UserAuthRequestMessage {
    init(request: NIOSSHUserAuthenticationRequest) {
        // We only ever ask for the ssh-connection service.
        self.username = request.username
        self.service = "ssh-connection"

        switch request.request {
        case .publicKey:
            fatalError("Unsupported")
        case .password(let passwordRequest):
            self.method = .password(passwordRequest.password)
        case .hostBased:
            fatalError("Unsupported")
        case .none:
            self.method = .none
        }
    }
}


extension NIOSSHUserAuthenticationRequest {
    init(_ message: SSHMessage.UserAuthRequestMessage) {
        self.username = message.username

        switch message.method {
        case .password(let password):
            self.request = .password(.init(password: password))
        case .none:
            self.request = .none
        }
    }
}


/// The outcome of a user authentication attempt.
public enum NIOSSHUserAuthenticationOutcome {
    case success
    case partialSuccess(remainingMethods: NIOSSHAvailableUserAuthenticationMethods)
    case failure
}


enum NIOSSHUserAuthenticationResponseMessage {
    case success
    case failure(SSHMessage.UserAuthFailureMessage)
}


extension NIOSSHUserAuthenticationResponseMessage {
    init(_ outcome: NIOSSHUserAuthenticationOutcome, supportedMethods: NIOSSHAvailableUserAuthenticationMethods) {
        switch outcome {
        case .success:
            self = .success
        case .partialSuccess(remainingMethods: let remaining):
            let message = SSHMessage.UserAuthFailureMessage(authentications: remaining.strings, partialSuccess: true)
            self = .failure(message)
        case .failure:
            let message = SSHMessage.UserAuthFailureMessage(authentications: supportedMethods.strings, partialSuccess: false)
            self = .failure(message)
        }
    }
}
