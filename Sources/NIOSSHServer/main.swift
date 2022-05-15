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

import Crypto
import Dispatch
import NIOCore
import NIOPosix
import NIOSSH

// This file contains an example NIO SSH server. It's not intended for production use, it's not secure,
// but it's a good example of how to
final class ErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Error in pipeline: \(error)")
        context.close(promise: nil)
    }
}

/// This delegate simply accepts a hardcoded password. For obvious reasons, don't deploy this!
final class HardcodedPasswordDelegate: NIOSSHServerUserAuthenticationDelegate {
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
        .password
    }

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        guard request.username == "nio", case .password(let passwordRequest) = request.request else {
            responsePromise.succeed(.failure)
            return
        }

        if passwordRequest.password == "gottagofast" {
            responsePromise.succeed(.success)
        } else {
            responsePromise.succeed(.failure)
        }
    }
}

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
defer {
    try! group.syncShutdownGracefully()
}

func sshChildChannelInitializer(_ channel: Channel, _ channelType: SSHChannelType) -> EventLoopFuture<Void> {
    switch channelType {
    case .session:
        return channel.pipeline.addHandler(ExampleExecHandler())
    case .directTCPIP(let target):
        let (ours, theirs) = GlueHandler.matchedPair()

        return channel.pipeline.addHandlers([DataToBufferCodec(), ours]).flatMap {
            createOutboundConnection(targetHost: target.targetHost, targetPort: target.targetPort, loop: channel.eventLoop)
        }.flatMap { targetChannel in
            targetChannel.pipeline.addHandler(theirs)
        }
    case .forwardedTCPIP:
        return channel.eventLoop.makeFailedFuture(SSHServerError.invalidChannelType)
    }
}

// We need a host key. For now, generate it dynamically.
let hostKey = NIOSSHPrivateKey(ed25519Key: .init())

let bootstrap = ServerBootstrap(group: group)
    .childChannelInitializer { channel in
        channel.pipeline.addHandlers([NIOSSHHandler(role: .server(.init(hostKeys: [hostKey], userAuthDelegate: HardcodedPasswordDelegate(), globalRequestDelegate: RemotePortForwarderGlobalRequestDelegate())), allocator: channel.allocator, inboundChildChannelInitializer: sshChildChannelInitializer(_:_:)), ErrorHandler()])
    }
    .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
    .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)

let channel = try bootstrap.bind(host: "0.0.0.0", port: 2222).wait()

// Run forever
try channel.closeFuture.wait()
