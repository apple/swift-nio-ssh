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

/// An object that controls multiplexing messages to multiple child channels.
final class SSHChannelMultiplexer {
    private var channels: [UInt32: SSHChildChannel]

    // This object can cause a reference cycle, so we require it to be optional so that we can
    // break the cycle manually.
    private var delegate: SSHMultiplexerDelegate?

    /// The next local channel ID to use. We cycle through them monotonically for now.
    private var nextChannelID: UInt32

    private let allocator: ByteBufferAllocator

    private var childChannelInitializer: ((Channel) -> EventLoopFuture<Void>)?

    init(delegate: SSHMultiplexerDelegate, allocator: ByteBufferAllocator, childChannelInitializer: ((Channel) -> EventLoopFuture<Void>)?) {
        self.channels = [:]
        self.channels.reserveCapacity(8)
        self.delegate = delegate
        self.nextChannelID = 0
        self.allocator = allocator
        self.childChannelInitializer = childChannelInitializer
    }

    // Time to clean up. We drop references to things that may be keeping us alive.
    // Note that we don't drop the child channels because we expect that they'll be cleaning themselves up.
    func parentHandlerRemoved() {
        self.delegate = nil
        self.childChannelInitializer = nil
    }
}

// MARK: Calls from child channels
extension SSHChannelMultiplexer {
    /// An `SSHChildChannel` has issued a write.
    func writeFromChannel(_ message: SSHMessage, _ promise: EventLoopPromise<Void>?) {
        guard let delegate = self.delegate else {
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }

        delegate.writeFromChildChannel(message, promise)
    }

    /// An `SSHChildChannel` has issued a flush.
    func childChannelFlush() {
        // Nothing to do.
        guard let delegate = self.delegate else {
            return
        }

        delegate.flushFromChildChannel()
    }

    func childChannelClosed(channelID: UInt32) {
        // This should never return `nil`, but we don't want to assert on it because
        // even if the object was never in the map, nothing bad will happen: it's gone!
        self.channels.removeValue(forKey: channelID)
    }
}

// MARK: Calls from SSH handlers.
extension SSHChannelMultiplexer {
    func receiveMessage(_ message: SSHMessage) throws {
        let channel: SSHChildChannel

        switch message {
        case .channelOpen:
            channel = try self.openNewChannel(initializer: self.childChannelInitializer)

        case .channelOpenConfirmation(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelOpenFailure(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelEOF(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelClose(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelWindowAdjust(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelData(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelExtendedData(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelRequest(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelSuccess(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        case .channelFailure(let message):
            channel = try self.existingChannel(localID: message.recipientChannel)

        default:
            // Not a channel message, we don't do anything more with this.
            return
        }

        // Deliver this message to the channel.
        channel.receiveInboundMessage(message)
    }

    func createChildChannel(_ promise: EventLoopPromise<Channel>? = nil, _ channelInitializer: ((Channel) -> EventLoopFuture<Void>)?) {
        do {
            let channel = try self.openNewChannel(initializer: channelInitializer)
            channel.configure(userPromise: promise)
        } catch {
            promise?.fail(error)
        }
    }

    func parentChannelReadComplete() {
        for channel in self.channels.values {
            channel.receiveParentChannelReadComplete()
        }
    }

    func parentChannelInactive() {
        for channel in self.channels.values {
            channel.parentChannelInactive()
        }
    }

    /// Opens a new channel and adds it to the multiplexer.
    private func openNewChannel(initializer: ((Channel) -> EventLoopFuture<Void>)?) throws -> SSHChildChannel {
        guard let parentChannel = self.delegate?.channel else {
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Opening new channel after channel shutdown")
        }

        // TODO: We need a better channel ID system. Maybe use indices into Arrays instead?
        let channelID = self.nextChannelID
        self.nextChannelID &+= 1

        // Int32.max isn't a spec-defined limit, but it's what OpenSSH uses as its upper bound. We will too.
        if self.nextChannelID > Int32.max {
            self.nextChannelID = 0
        }

        // TODO: Make the window management parameters configurable
        let channel = SSHChildChannel(allocator: self.allocator,
                                      parent: parentChannel,
                                      multiplexer: self,
                                      initializer: initializer,
                                      localChannelID: channelID,
                                      targetWindowSize: 1 << 24,
                                      initialOutboundWindowSize: 0)  // The initial outbound window size is presumed to be 0 until we're told otherwise.

        self.channels[channelID] = channel
        return channel
    }

    private func existingChannel(localID: UInt32) throws -> SSHChildChannel {
        guard let channel = self.channels[localID] else {
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Unexpected request with local channel id \(localID)")
        }
        return channel
    }
}

/// An internal protocol to encapsulate the object that owns the multiplexer.
protocol SSHMultiplexerDelegate {
    var channel: Channel? { get }

    func writeFromChildChannel(_: SSHMessage, _: EventLoopPromise<Void>?)

    func flushFromChildChannel()
}
