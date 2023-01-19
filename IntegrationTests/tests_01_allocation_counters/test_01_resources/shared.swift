//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import NIOCore
import NIOEmbedded
import NIOSSH

final class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        // Do not replicate this in your own code: validate host keys! This is a
        // choice made for expedience, not for any other reason.
        validationCompletePromise.succeed(())
    }
}

final class HardcodedClientPasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        precondition(availableMethods.contains(.password))
        nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: "username", serviceName: "", offer: .password(.init(password: "password"))))
    }
}

final class HardcodedServerPasswordDelegate: NIOSSHServerUserAuthenticationDelegate {
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
        .password
    }

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        guard request.username == "username", case .password(let passwordRequest) = request.request else {
            responsePromise.succeed(.failure)
            return
        }

        if passwordRequest.password == "password" {
            responsePromise.succeed(.success)
        } else {
            responsePromise.succeed(.failure)
        }
    }
}

/// Have two `EmbeddedChannel` objects send and receive data from each other until
/// they make no forward progress.
func interactInMemory(_ first: EmbeddedChannel, _ second: EmbeddedChannel) throws {
    var operated: Bool

    func readBytesFromChannel(_ channel: EmbeddedChannel) throws -> ByteBuffer? {
        try channel.readOutbound(as: ByteBuffer.self)
    }

    repeat {
        operated = false
        first.embeddedEventLoop.run()

        if let data = try readBytesFromChannel(first) {
            operated = true
            try second.writeInbound(data)
        }
        if let data = try readBytesFromChannel(second) {
            operated = true
            try first.writeInbound(data)
        }
    } while operated
}
