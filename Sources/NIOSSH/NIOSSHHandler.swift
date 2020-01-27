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

import NIO


/// A `ChannelDuplexHandler` that implements the SSH protocol.
///
/// SSH is a protocol originally designed to negotiate a secure transportation channel over
/// which a login shell can be run. This allows users to remotely log in to machines and
/// administrate them over the network securely.
///
/// However, in addition to the ability to open a remote shell, SSH supports a number of
/// other usage models, including port forwarding. It is also able to construct somewhat
/// arbitrary secure multiplexed channels.
public final class NIOSSHHandler {
    /// The state machine that drives the connection.
    private var stateMachine: SSHConnectionStateMachine

    /// A buffer used to provide scratch space for writing data to the network.
    ///
    /// This is an IUO because it should never be nil, but it is only initialized once the
    /// handler is added to a channel.
    private var outboundFrameBuffer: ByteBuffer

    /// Whether there's a pending unflushed write.
    private var pendingWrite: Bool

    public init(role: SSHConnectionRole, allocator: ByteBufferAllocator) {
        self.stateMachine = SSHConnectionStateMachine(role: role, allocator: allocator)
        self.pendingWrite = false
        self.outboundFrameBuffer = allocator.buffer(capacity: 1024)
    }
}



extension NIOSSHHandler: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    public typealias InboundOut = Never  // Temporary
    public typealias OutboundIn = Never  // Temporary

    public func channelActive(context: ChannelHandlerContext) {
        // The connection is active, let's go yo. We have to flush here.
        let message = self.stateMachine.start()

        do {
            try self.writeMessage(message, context: context)
            self.pendingWrite = false
            context.flush()
            context.fireChannelActive()
        } catch {
            context.fireErrorCaught(error)
        }
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var data = self.unwrapInboundIn(data)
        self.stateMachine.parser.append(bytes: &data)

        do {
            while let message = try self.stateMachine.parser.nextPacket() {
                try self.processInboundMessage(message, context: context)
            }
        } catch {
            context.fireErrorCaught(error)
        }
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        if self.pendingWrite {
            self.pendingWrite = false
            context.flush()
        }
    }

    private func writeMessage(_ message: SSHMessage, context: ChannelHandlerContext) throws {
        self.outboundFrameBuffer.clear()
        try self.stateMachine.serializer.serialize(message: message, to: &self.outboundFrameBuffer)
        self.pendingWrite = true
        context.write(self.wrapOutboundOut(self.outboundFrameBuffer), promise: nil)
    }

    private func processInboundMessage(_ message: SSHMessage, context: ChannelHandlerContext) throws {
        let result = try self.stateMachine.processInboundMessage(allocator: context.channel.allocator, message: message)

        switch result {
        case .emitMessage(let message):
            try self.writeMessage(message, context: context)
        case .noMessage:
            break
        case .possibleFutureMessage(let future):
            // TODO(cory): This is not right, but for now it's good enough.
            future.whenComplete { result in
                switch result {
                case .success(.some(let message)):
                    do {
                        try self.writeMessage(message, context: context)
                    } catch {
                        context.fireErrorCaught(error)
                    }
                case .success(.none):
                    // Do nothing
                    break
                case .failure(let error):
                    context.fireErrorCaught(error)
                }
            }
        }
    }
}


extension NIOSSHHandler {
    private var isClient: Bool {
        return self.stateMachine.role.isClient
    }
}
