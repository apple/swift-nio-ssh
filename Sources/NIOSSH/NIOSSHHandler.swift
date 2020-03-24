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
    internal var channel: Channel? {
        return self.context.map { $0.channel }
    }

    /// The state machine that drives the connection.
    private var stateMachine: SSHConnectionStateMachine

    /// A buffer used to provide scratch space for writing data to the network.
    ///
    /// This is an IUO because it should never be nil, but it is only initialized once the
    /// handler is added to a channel.
    private var outboundFrameBuffer: ByteBuffer

    /// Whether there's a pending unflushed write.
    private var pendingWrite: Bool

    /// The user-auth delegate for this connection.
    private let authDelegate: UserAuthDelegate

    private var context: ChannelHandlerContext?

    // Must be optional as we need to pass it a reference to self.
    private var multiplexer: SSHChannelMultiplexer?

    // Whether we're expecting a channelReadComplete.
    private var expectingChannelReadComplete: Bool = false

    // A buffer of pending channel initializations. A channel initialization is pending if
    // we're attempting to initialize a channel before user auth is complete.
    private var pendingChannelInitializations: CircularBuffer<(promise: EventLoopPromise<Channel>?, initializer: ((Channel) -> EventLoopFuture<Void>)?)>

    public init(role: SSHConnectionRole, allocator: ByteBufferAllocator, clientUserAuthDelegate: NIOSSHClientUserAuthenticationDelegate?, serverUserAuthDelegate: NIOSSHServerUserAuthenticationDelegate?, inboundChildChannelInitializer: ((Channel) -> EventLoopFuture<Void>)?) {
        self.stateMachine = SSHConnectionStateMachine(role: role)
        self.pendingWrite = false
        self.outboundFrameBuffer = allocator.buffer(capacity: 1024)
        self.authDelegate = UserAuthDelegate(role: role, client: clientUserAuthDelegate, server: serverUserAuthDelegate)
        self.pendingChannelInitializations = CircularBuffer(initialCapacity: 4)
        self.multiplexer = SSHChannelMultiplexer(delegate: self, allocator: allocator, childChannelInitializer: inboundChildChannelInitializer)
    }
}



extension NIOSSHHandler: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    public typealias InboundOut = Never  // Temporary
    public typealias OutboundIn = Never  // Temporary

    public func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil

        // We don't actually need to nil out the multiplexer here (it will nil its reference to us)
        // but we _can_, and it doesn't hurt.
        self.multiplexer?.parentHandlerRemoved()
        self.multiplexer = nil
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

    public func channelInactive(context: ChannelHandlerContext) {
        self.multiplexer?.parentChannelInactive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self.expectingChannelReadComplete = true

        var data = self.unwrapInboundIn(data)
        self.stateMachine.bufferInboundData(&data)

        do {
            while let result = try self.stateMachine.processInboundMessage(allocator: context.channel.allocator, loop: context.eventLoop, userAuthDelegate: self.authDelegate) {
                try self.processInboundMessageResult(result, context: context)
            }
        } catch {
            context.fireErrorCaught(error)
        }
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        self.multiplexer?.parentChannelReadComplete()
        self.expectingChannelReadComplete = false

        if self.pendingWrite {
            self.pendingWrite = false
            context.flush()
        }

        self.createPendingChannelsIfPossible()
    }

    private func writeMessage(_ multiMessage: SSHMultiMessage, context: ChannelHandlerContext, promise: EventLoopPromise<Void>? = nil) throws {
        self.outboundFrameBuffer.clear()

        for message in multiMessage {
            try self.stateMachine.processOutboundMessage(message, buffer: &self.outboundFrameBuffer, allocator: context.channel.allocator, loop: context.eventLoop, userAuthDelegate: self.authDelegate)
            self.pendingWrite = true
        }

        context.write(self.wrapOutboundOut(self.outboundFrameBuffer), promise: promise)
    }

    private func processInboundMessageResult(_ result: SSHConnectionStateMachine.StateMachineInboundProcessResult, context: ChannelHandlerContext) throws {
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
                        self.pendingWrite = false
                        context.flush()
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
        case .forwardToMultiplexer(let message):
            try self.multiplexer?.receiveMessage(message)
        }
    }
}

// MARK: Create a child channel
extension NIOSSHHandler {
    public func createChannel(_ promise: EventLoopPromise<Channel>? = nil, _ channelInitializer: ((Channel) -> EventLoopFuture<Void>)?) {
        self.pendingChannelInitializations.append((promise: promise, initializer: channelInitializer))
        self.createPendingChannelsIfPossible()
    }

    private func createPendingChannelsIfPossible() {
        guard self.stateMachine.canInitializeChildChannels && self.pendingChannelInitializations.count > 0 else {
            // No work to do
            return
        }

        if let multiplexer = self.multiplexer {
            while let next = self.pendingChannelInitializations.popFirst() {
                multiplexer.createChildChannel(next.promise, next.initializer)
            }
        } else {
            while let next = self.pendingChannelInitializations.popFirst() {
                next.promise?.fail(NIOSSHError.creatingChannelAfterClosure)
            }
        }
    }
}

// MARK: Functions called from the multiplexer
extension NIOSSHHandler: SSHMultiplexerDelegate {
    func writeFromChildChannel(_ message: SSHMessage, _ promise: EventLoopPromise<Void>?) {
        guard let context = self.context else {
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }

        do {
            try self.writeMessage(SSHMultiMessage(message), context: context, promise: promise)
        } catch {
            promise?.fail(error)
        }
    }

    func flushFromChildChannel() {
        // If a child channel flushes and we aren't in a channelReadComplete loop, we need to flush. Otherwise
        // we can just wait.
        if !self.expectingChannelReadComplete {
            self.context?.flush()
        }
    }
}
