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

    /// An SSH packet parser.
    private var parser: SSHPacketParser?

    /// An SSH packet serializer.
    private var serializer: SSHPacketSerializer

    /// A buffer used to provide scratch space for writing data to the network.
    ///
    /// This is an IUO because it should never be nil, but it is only initialized once the
    /// handler is added to a channel.
    private var outboundFrameBuffer: ByteBuffer?

    /// Whether there's a pending unflushed write.
    private var pendingWrite: Bool

    public init(role: SSHConnectionRole) {
        self.stateMachine = SSHConnectionStateMachine(role: role)
        self.pendingWrite = false
        self.serializer = SSHPacketSerializer()
    }
}



extension NIOSSHHandler: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    public typealias InboundOut = Never  // Temporary
    public typealias OutboundIn = Never  // Temporary

    public func handlerAdded(context: ChannelHandlerContext) {
        // 1kB is a decent size scratch buffer for now.
        self.outboundFrameBuffer = context.channel.allocator.buffer(capacity: 1024)
        self.parser = SSHPacketParser(allocator: context.channel.allocator)
    }

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
        self.parser!.append(bytes: &data)

        do {
            while let message = try self.parser!.nextPacket() {
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
        // We swap the buffer off self to mutate it, but we make sure we put it back before
        // we write to ensure we're safe for re-entrancy.
        guard var buffer = self.outboundFrameBuffer else {
            preconditionFailure("Failed to initialize frame buffer before writing a message")
        }
        self.outboundFrameBuffer = nil

        buffer.clear()
        try self.serializer.serialize(message: message, to: &buffer)
        self.outboundFrameBuffer = buffer
        self.pendingWrite = true
        context.write(self.wrapOutboundOut(buffer), promise: nil)
    }

    private func processInboundMessage(_ message: SSHMessage, context: ChannelHandlerContext) throws {
        guard let message = try self.stateMachine.process(allocator: context.channel.allocator, message: message) else {
            // Nothing to do here
            return
        }

        try self.writeMessage(message, context: context)
    }
}


extension NIOSSHHandler {
    private var isClient: Bool {
        return self.stateMachine.role.isClient
    }
}
