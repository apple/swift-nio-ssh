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

internal enum UserAuthDelegate {
    case server(NIOSSHServerUserAuthenticationDelegate)
    case client(NIOSSHClientUserAuthenticationDelegate)

    init(role: SSHConnectionRole, client: NIOSSHClientUserAuthenticationDelegate?, server: NIOSSHServerUserAuthenticationDelegate?) {
        switch (role, client, server) {
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
        case (.server, _, .some):
            preconditionFailure("Servers may not have client user auth delegates")
        }
    }
}
