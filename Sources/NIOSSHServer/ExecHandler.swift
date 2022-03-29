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
import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix
import NIOSSH

enum SSHServerError: Error {
    case invalidCommand
    case invalidDataType
    case invalidChannelType
    case alreadyListening
    case notListening
}

final class ExampleExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    let queue = DispatchQueue(label: "background exec")
    var process: Process?
    var environment: [String: String] = [:]

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        self.queue.sync {
            if let process = self.process, process.isRunning {
                process.terminate()
            }
        }
        context.fireChannelInactive()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as SSHChannelRequestEvent.ExecRequest:
            self.exec(event, channel: context.channel)

        case let event as SSHChannelRequestEvent.EnvironmentRequest:
            self.queue.sync {
                environment[event.name] = event.value
            }

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(let bytes) = data.data else {
            fatalError("Unexpected read type")
        }

        guard case .channel = data.type else {
            context.fireErrorCaught(SSHServerError.invalidDataType)
            return
        }

        context.fireChannelRead(self.wrapInboundOut(bytes))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(data))), promise: promise)
    }

    private func exec(_ event: SSHChannelRequestEvent.ExecRequest, channel: Channel) {
        // Kick this off to a background queue
        self.queue.async {
            do {
                // We're not a shell, so we just do our "best".
                let executable = URL(fileURLWithPath: "/usr/local/bin/bash")
                let process = Process()
                process.executableURL = executable
                process.arguments = ["-c", event.command]
                process.terminationHandler = { process in
                    // The process terminated. Check its return code, fire it, and then move on.
                    let rcode = process.terminationStatus
                    channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ExitStatus(exitStatus: Int(rcode))).whenComplete { _ in
                        channel.close(promise: nil)
                    }
                }

                let inPipe = Pipe()
                let outPipe = Pipe()
                let errPipe = Pipe()

                process.standardInput = inPipe
                process.standardOutput = outPipe
                process.standardError = errPipe
                process.environment = self.environment

                let (ours, theirs) = GlueHandler.matchedPair()
                try channel.pipeline.addHandler(ours).wait()

                _ = try NIOPipeBootstrap(group: channel.eventLoop)
                    .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                    .channelInitializer { pipeChannel in
                        pipeChannel.pipeline.addHandler(theirs)
                    }.withPipes(inputDescriptor: outPipe.fileHandleForReading.fileDescriptor, outputDescriptor: inPipe.fileHandleForWriting.fileDescriptor).wait()

                // Ok, great, we've sorted stdout and stdin. For stderr we need a different strategy: we just park a thread for this.
                DispatchQueue(label: "stderrorwhatever").async {
                    while true {
                        let data = errPipe.fileHandleForReading.readData(ofLength: 1024)

                        guard data.count > 0 else {
                            // Stderr is done
                            return
                        }

                        var buffer = channel.allocator.buffer(capacity: data.count)
                        buffer.writeContiguousBytes(data)
                        channel.write(SSHChannelData(type: .stdErr, data: .byteBuffer(buffer)), promise: nil)
                    }
                }

                if event.wantReply {
                    channel.triggerUserOutboundEvent(ChannelSuccessEvent(), promise: nil)
                }

                try process.run()
                self.process = process
            } catch {
                if event.wantReply {
                    channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                        channel.close(promise: nil)
                    }
                } else {
                    channel.close(promise: nil)
                }
            }
        }
    }
}
