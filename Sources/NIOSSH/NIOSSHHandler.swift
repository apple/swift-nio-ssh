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
        self.context.map { $0.channel }
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

    private var context: ChannelHandlerContext?

    // Must be optional as we need to pass it a reference to self.
    private var multiplexer: SSHChannelMultiplexer?

    // Whether we're expecting a channelReadComplete.
    private var expectingChannelReadComplete: Bool = false

    // A buffer of pending channel initializations. A channel initialization is pending if
    // we're attempting to initialize a channel before user auth is complete.
    private var pendingChannelInitializations: CircularBuffer<(promise: EventLoopPromise<Channel>?, channelType: SSHChannelType, initializer: SSHChildChannel.Initializer?)>

    // A buffer of pending global requests. A global request is pending if we tried to send it before user auth completed.
    private var pendingGlobalRequests: CircularBuffer<(SSHMessage.GlobalRequestMessage, EventLoopPromise<GlobalRequest.GlobalRequestResponse>?)>

    private var pendingGlobalRequestResponses: CircularBuffer<EventLoopPromise<GlobalRequest.GlobalRequestResponse>?>

    public init(role: SSHConnectionRole, allocator: ByteBufferAllocator, inboundChildChannelInitializer: ((Channel, SSHChannelType) -> EventLoopFuture<Void>)?) {
        self.stateMachine = SSHConnectionStateMachine(role: role)
        self.pendingWrite = false
        self.outboundFrameBuffer = allocator.buffer(capacity: 1024)
        self.pendingChannelInitializations = CircularBuffer(initialCapacity: 4)
        self.pendingGlobalRequests = CircularBuffer(initialCapacity: 4)
        self.pendingGlobalRequestResponses = CircularBuffer(initialCapacity: 4)
        self.multiplexer = SSHChannelMultiplexer(delegate: self, allocator: allocator, childChannelInitializer: inboundChildChannelInitializer)
    }
}

extension NIOSSHHandler: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    public typealias InboundOut = Never // Temporary
    public typealias OutboundIn = Never // Temporary

    public func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil

        // We don't actually need to nil out the multiplexer here (it will nil its reference to us)
        // but we _can_, and it doesn't hurt.
        self.multiplexer?.parentHandlerRemoved()
        self.multiplexer = nil

        self.dropAllPendingGlobalRequests(ChannelError.eof)
        self.dropUnsatisfiedGlobalRequests(ChannelError.eof)
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
            while let result = try self.stateMachine.processInboundMessage(allocator: context.channel.allocator, loop: context.eventLoop) {
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
        self.sendGlobalRequestsIfPossible()
    }

    private func writeMessage(_ multiMessage: SSHMultiMessage, context: ChannelHandlerContext, promise: EventLoopPromise<Void>? = nil) throws {
        self.outboundFrameBuffer.clear()

        for message in multiMessage {
            try self.stateMachine.processOutboundMessage(message, buffer: &self.outboundFrameBuffer, allocator: context.channel.allocator, loop: context.eventLoop)
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
        case .globalRequest(let message):
            try self.handleGlobalRequest(message)
        case .globalRequestResponse(let response):
            try self.handleGlobalRequestResponse(response)
        case .disconnect:
            // Welp, we immediately have to close.
            context.close(promise: nil)
        }
    }
}

// MARK: Create a child channel

extension NIOSSHHandler {
    /// Creates an SSH channel.
    ///
    /// This function is **not** thread-safe: it may only be called from on the channel.
    ///
    /// - parameters:
    ///     - promise: An `EventLoopPromise` that will be fulfilled with the channel when it becomes active.
    ///     - channelType: The type of the channel to create. Defaults to `.session` for running remote processes.
    ///     - channelInitializer: A callback that will be invoked to initialize the channel.
    public func createChannel(_ promise: EventLoopPromise<Channel>? = nil, channelType: SSHChannelType = .session, _ channelInitializer: ((Channel, SSHChannelType) -> EventLoopFuture<Void>)?) {
        self.pendingChannelInitializations.append((promise: promise, channelType: channelType, initializer: channelInitializer))
        self.createPendingChannelsIfPossible()
    }

    private func createPendingChannelsIfPossible() {
        guard self.stateMachine.isActive, self.pendingChannelInitializations.count > 0 else {
            // No work to do
            return
        }

        if let multiplexer = self.multiplexer {
            while let next = self.pendingChannelInitializations.popFirst() {
                multiplexer.createChildChannel(next.promise, channelType: next.channelType, next.initializer)
            }
        } else {
            while let next = self.pendingChannelInitializations.popFirst() {
                next.promise?.fail(NIOSSHError.creatingChannelAfterClosure)
            }
        }
    }
}

// MARK: Create a global request

extension NIOSSHHandler {
    /// Send a TCP forwarding request, either to initiate or cancel remote TCP forwarding.
    ///
    /// This function is **not** thread-safe: it may only be called from on the channel.
    ///
    /// - parameters:
    ///     - request: The request to send.
    ///     - promise: An `EventLoopPromise` that will be fulfilled when the request is accepted. Will error
    ///         if the request was rejected or could not be sent.
    public func sendTCPForwardingRequest(_ request: GlobalRequest.TCPForwardingRequest, promise: EventLoopPromise<GlobalRequest.GlobalRequestResponse>? = nil) {
        let message = SSHMessage.GlobalRequestMessage(wantReply: true, type: .init(request))
        self.pendingGlobalRequests.append((value: message, promise: promise))
        self.sendGlobalRequestsIfPossible()
    }

    fileprivate func dropAllPendingGlobalRequests(_ error: Error) {
        while let next = self.pendingGlobalRequests.popFirst() {
            next.1?.fail(error)
        }
    }

    fileprivate func dropUnsatisfiedGlobalRequests(_ error: Error) {
        while let next = self.pendingGlobalRequestResponses.popFirst() {
            next?.fail(error)
        }
    }

    fileprivate func handleGlobalRequestResponse(_ response: SSHConnectionStateMachine.StateMachineInboundProcessResult.GlobalRequestResponse) throws {
        guard let next = self.pendingGlobalRequestResponses.popFirst() else {
            throw NIOSSHError.unexpectedGlobalRequestResponse
        }

        switch response {
        case .success(let response):
            next?.succeed(.init(response))
        case .failure:
            next?.fail(NIOSSHError.globalRequestRefused)
        }
    }

    fileprivate func handleGlobalRequest(_ message: SSHMessage.GlobalRequestMessage) throws {
        guard let context = context else {
            // Weird, somehow we're out of the channel now. Drop this.
            return
        }

        let responsePromise = context.eventLoop.makePromise(of: GlobalRequest.GlobalRequestResponse.self)
        responsePromise.futureResult.whenComplete { result in
            guard message.wantReply else {
                // Nothing to do.
                return
            }

            do {
                switch result {
                case .success(let response):
                    try self.writeMessage(.init(.requestSuccess(.init(response))), context: context)
                    context.flush()

                case .failure:
                    // We don't care why, we just say no.
                    try self.writeMessage(.init(.requestFailure), context: context)
                    context.flush()
                }
            } catch {
                context.fireErrorCaught(error)
            }
        }
        
        switch message.type {
        case .unknown:
            if message.wantReply {
                // There's no way to tell what message this is and how to respond from here.
                // The only reasonable solution is to reply `SSH_MSG_REQUEST_FAILURE`
                try self.writeMessage(.init(.requestFailure), context: context)
                context.flush()
            }
        case .tcpipForward(let host, let port):
            switch self.stateMachine.role {
            case .client(let config):
                config.globalRequestDelegate.tcpForwardingRequest(.listen(host: host, port: Int(port)), handler: self, promise: responsePromise)
            case .server(let config):
                config.globalRequestDelegate.tcpForwardingRequest(.listen(host: host, port: Int(port)), handler: self, promise: responsePromise)
            }
        case .cancelTcpipForward(let host, let port):
            switch self.stateMachine.role {
            case .client(let config):
                config.globalRequestDelegate.tcpForwardingRequest(.cancel(host: host, port: Int(port)), handler: self, promise: responsePromise)
            case .server(let config):
                config.globalRequestDelegate.tcpForwardingRequest(.cancel(host: host, port: Int(port)), handler: self, promise: responsePromise)
            }
        }
    }

    private func sendGlobalRequestsIfPossible() {
        guard let context = self.context else {
            self.dropAllPendingGlobalRequests(ChannelError.ioOnClosedChannel)
            return
        }

        guard self.stateMachine.isActive, self.pendingGlobalRequests.count > 0 else {
            // No work to do
            return
        }

        var didSend = false
        while let next = self.pendingGlobalRequests.popFirst() {
            didSend = true
            self.sendGlobalRequest(next.0, promise: next.1, context: context)
        }

        if didSend {
            context.flush()
        }
    }

    private func sendGlobalRequest(_ request: SSHMessage.GlobalRequestMessage, promise: EventLoopPromise<GlobalRequest.GlobalRequestResponse>?, context: ChannelHandlerContext) {
        // Sending a single global request is tricky, because we don't want to succeed the promise until we have the result of the
        // request. That means we need a buffer of promises for request success/failure messages, as well as to create new promises.
        let writePromise = context.eventLoop.makePromise(of: Void.self)
        writePromise.futureResult.whenComplete { result in
            switch result {
            case .success:
                guard self.context != nil else {
                    // This write succeeded, but we're out of the pipeline anyway. Fail the promise.
                    promise?.fail(ChannelError.eof)
                    return
                }

                // Great, we're still active. Now we wait for a response.
                // We add the nil promise here too to maintain ordering.
                self.pendingGlobalRequestResponses.append(promise)

            case .failure(let error):
                promise?.fail(error)
            }
        }

        do {
            try self.writeMessage(.init(.globalRequest(request)), context: context, promise: writePromise)
        } catch {
            writePromise.fail(error)
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
