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

    init(role: SSHConnectionRole) {
        switch role {
        case .client(let config):
            self = .client(config.userAuthDelegate)
        case .server(let config):
            self = .server(config.userAuthDelegate)
        }
    }
}
