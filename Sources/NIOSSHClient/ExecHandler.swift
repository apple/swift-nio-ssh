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

final class ExampleExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    private var completePromise: EventLoopPromise<Int>?

    private let command: String

    init(command: String, completePromise: EventLoopPromise<Int>) {
        self.completePromise = completePromise
        self.command = command
    }

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        // We need to set up a pipe channel and glue it to this. This will control our I/O.
        let (ours, theirs) = GlueHandler.matchedPair()

        // Sadly we have to kick off to a background thread to bootstrap the pipe channel.
        let bootstrap = NIOPipeBootstrap(group: context.eventLoop)
        context.channel.pipeline.addHandler(ours, position: .last).whenSuccess { _ in
            DispatchQueue(label: "pipe bootstrap").async {
                bootstrap.channelOption(ChannelOptions.allowRemoteHalfClosure, value: true).channelInitializer { channel in
                    channel.pipeline.addHandler(theirs)
                }.withPipes(inputDescriptor: 0, outputDescriptor: 1).whenComplete { result in
                    switch result {
                    case .success:
                        // We need to exec a thing.
                        let execRequest = SSHChannelRequestEvent.ExecRequest(command: self.command, wantReply: false)
                        context.triggerUserOutboundEvent(execRequest).whenFailure { _ in
                            context.close(promise: nil)
                        }
                    case .failure(let error):
                        context.fireErrorCaught(error)
                    }
                }
            }
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as SSHChannelRequestEvent.ExitStatus:
            if let promise = self.completePromise {
                self.completePromise = nil
                promise.succeed(event.exitStatus)
            }

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        if let promise = self.completePromise {
            self.completePromise = nil
            promise.fail(SSHClientError.commandExecFailed)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(let bytes) = data.data else {
            fatalError("Unexpected read type")
        }

        switch data.type {
        case .channel:
            // Channel data is forwarded on, the pipe channel will handle it.
            context.fireChannelRead(self.wrapInboundOut(bytes))
            return

        case .stdErr:
            // We just write to stderr directly, pipe channel can't help us here.
            bytes.withUnsafeReadableBytes { str in
                let rc = fwrite(str.baseAddress, 1, str.count, stderr)
                precondition(rc == str.count)
            }

        default:
            fatalError("Unexpected message type")
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(data))), promise: promise)
    }
}

enum SSHClientError: Swift.Error {
    case passwordAuthenticationNotSupported
    case commandExecFailed
    case invalidChannelType
    case invalidData
}
