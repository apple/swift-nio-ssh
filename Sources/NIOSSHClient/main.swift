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
import NIO
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

// Let's try creating a child channel.
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
