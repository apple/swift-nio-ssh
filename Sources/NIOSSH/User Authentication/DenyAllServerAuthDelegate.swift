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

/// A server user authentication delegate that denies all authentication attempts.
///
/// Not really useful in and of itself, but a helpful default option.
public final class DenyAllServerAuthDelegate {}

extension DenyAllServerAuthDelegate: NIOSSHServerUserAuthenticationDelegate {
    public var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
        .all
    }

    public func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        responsePromise.succeed(.failure)
    }
}
