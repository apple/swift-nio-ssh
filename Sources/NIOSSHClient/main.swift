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
import NIOCore
import NIOPosix
import NIOSSH

// This file contains an example NIO SSH client. As NIO SSH is currently under active
// development this file doesn't currently do all that much, but it does provide a binary you
// can kick off to get a feel for how NIO SSH drives the connection live. As the feature set of
// NIO SSH increases we'll be adding to this client to try to make it a better example of what you
// can do with NIO SSH.
final class ErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Error in pipeline: \(error)")
        context.close(promise: nil)
    }
}

final class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        // Do not replicate this in your own code: validate host keys! This is a
        // choice made for expedience, not for any other reason.
        validationCompletePromise.succeed(())
    }
}

let parser = SimpleCLIParser()
let parseResult = parser.parse()

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
defer {
    try! group.syncShutdownGracefully()
}

let bootstrap = ClientBootstrap(group: group)
    .channelInitializer { channel in
        channel.pipeline.addHandlers([NIOSSHHandler(role: .client(.init(userAuthDelegate: InteractivePasswordPromptDelegate(username: parseResult.user, password: parseResult.password), serverAuthDelegate: AcceptAllHostKeysDelegate())), allocator: channel.allocator, inboundChildChannelInitializer: nil), ErrorHandler()])
    }
    .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
    .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)

let channel = try bootstrap.connect(host: parseResult.host, port: parseResult.port).wait()

if let listen = parseResult.listen {
    // We've been asked to port forward.
    let server = PortForwardingServer(group: group,
                                      bindHost: listen.bindHost ?? "localhost",
                                      bindPort: listen.bindPort) { inboundChannel in
        // This block executes whenever a new inbound channel is received. We want to forward it to the peer.
        // To do that, we have to begin by creating a new SSH channel of the appropriate type.
        channel.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
            let promise = inboundChannel.eventLoop.makePromise(of: Channel.self)
            let directTCPIP = SSHChannelType.DirectTCPIP(targetHost: String(listen.targetHost),
                                                         targetPort: listen.targetPort,
                                                         originatorAddress: inboundChannel.remoteAddress!)
            sshHandler.createChannel(promise,
                                     channelType: .directTCPIP(directTCPIP)) { childChannel, channelType in
                guard case .directTCPIP = channelType else {
                    return channel.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                }

                // Attach a pair of glue handlers, one in the inbound channel and one in the outbound one.
                // We also add an error handler to both channels, and a wrapper handler to the SSH child channel to
                // encapsulate the data in SSH messages.
                // When the glue handlers are in, we can create both channels.
                let (ours, theirs) = GlueHandler.matchedPair()
                return childChannel.pipeline.addHandlers([SSHWrapperHandler(), ours, ErrorHandler()]).flatMap {
                    inboundChannel.pipeline.addHandlers([theirs, ErrorHandler()])
                }
            }

            // We need to erase the channel here: we just want success or failure info.
            return promise.futureResult.map { _ in }
        }
    }

    // Run the server until complete
    try! server.run().wait()

} else {
    // We've been asked to exec.
    let exitStatusPromise = channel.eventLoop.makePromise(of: Int.self)
    let childChannel: Channel = try! channel.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
        let promise = channel.eventLoop.makePromise(of: Channel.self)
        sshHandler.createChannel(promise) { childChannel, channelType in
            guard channelType == .session else {
                return channel.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
            }
            return childChannel.pipeline.addHandlers([ExampleExecHandler(command: parseResult.commandString, completePromise: exitStatusPromise), ErrorHandler()])
        }
        return promise.futureResult
    }.wait()

    // Wait for the connection to close
    try childChannel.closeFuture.wait()
    let exitStatus = try! exitStatusPromise.futureResult.wait()
    try! channel.close().wait()

    // Exit like we're the command.
    exit(Int32(exitStatus))
}
