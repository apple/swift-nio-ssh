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

import NIOCore

/// An object that controls multiplexing messages to multiple child channels.
final class SSHChannelMultiplexer {
    private var channels: [UInt32: SSHChildChannel]

    private var erroredChannels: [UInt32]

    // This object can cause a reference cycle, so we require it to be optional so that we can
    // break the cycle manually.
    private var delegate: SSHMultiplexerDelegate?

    /// The next local channel ID to use. We cycle through them monotonically for now.
    private var nextChannelID: UInt32

    private let allocator: ByteBufferAllocator

    private var childChannelInitializer: SSHChildChannel.Initializer?

    /// Whether new channels are allowed. Set to `false` once the parent channel is shut down at the TCP level.
    private var canCreateNewChannels: Bool

    private let maximumPacketSize: Int

    init(delegate: SSHMultiplexerDelegate, allocator: ByteBufferAllocator, childChannelInitializer: SSHChildChannel.Initializer?, maximumPacketSize: Int = 1 << 17) {
        self.channels = [:]
        self.channels.reserveCapacity(8)
        self.erroredChannels = []
        self.delegate = delegate
        self.nextChannelID = 0
        self.allocator = allocator
        self.childChannelInitializer = childChannelInitializer
        self.canCreateNewChannels = true
        self.maximumPacketSize = maximumPacketSize
    }

    // Time to clean up. We drop references to things that may be keeping us alive.
    // Note that we don't drop the child channels because we expect that they'll be cleaning themselves up.
    func parentHandlerRemoved() {
        self.delegate = nil
        self.childChannelInitializer = nil
        self.canCreateNewChannels = false
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

    func childChannelErrored(channelID: UInt32, expectClose: Bool) {
        // This should never return `nil`, but we don't want to assert on it because
        // even if the object was never in the map, nothing bad will happen: it's gone!
        self.channels.removeValue(forKey: channelID)

        if expectClose {
            // We keep track of the errored channel because we will tolerate receiving a close for it.
            self.erroredChannels.append(channelID)
        }
    }
}

// MARK: Calls from SSH handlers.

extension SSHChannelMultiplexer {
    func receiveMessage(_ message: SSHMessage) throws {
        let channel: SSHChildChannel?

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
            if channel == nil, let errorIndex = self.erroredChannels.firstIndex(of: message.recipientChannel) {
                // This is the end of our need to keep track of the channel.
                self.erroredChannels.remove(at: errorIndex)
            }

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

        if let channel = channel {
            channel.receiveInboundMessage(message)
        }
    }

    func createChildChannel(_ promise: EventLoopPromise<Channel>? = nil, channelType: SSHChannelType, _ channelInitializer: SSHChildChannel.Initializer?) {
        do {
            let channel = try self.openNewChannel(initializer: channelInitializer)
            channel.configure(userPromise: promise, channelType: channelType)
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
        self.canCreateNewChannels = false
        for channel in self.channels.values {
            channel.parentChannelInactive()
        }
    }

    /// Opens a new channel and adds it to the multiplexer.
    private func openNewChannel(initializer: SSHChildChannel.Initializer?) throws -> SSHChildChannel {
        guard let parentChannel = self.delegate?.channel else {
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Opening new channel after channel shutdown")
        }

        guard self.canCreateNewChannels else {
            throw NIOSSHError.tcpShutdown
        }

        // TODO: We need a better channel ID system. Maybe use indices into Arrays instead?
        let channelID = self.nextChannelID
        self.nextChannelID &+= 1

        // Int32.max isn't a spec-defined limit, but it's what OpenSSH uses as its upper bound. We will too.
        if self.nextChannelID > Int32.max {
            self.nextChannelID = 0
        }

        // `maximumPacketSize` can be safely cast, because overrides of the default by implementations are expected to have sensible values
        // These are also asserted in SSHPackageParser.init
        let channel = SSHChildChannel(allocator: self.allocator,
                                      parent: parentChannel,
                                      multiplexer: self,
                                      initializer: initializer,
                                      localChannelID: channelID,
                                      targetWindowSize: Int32(self.maximumPacketSize),
                                      initialOutboundWindowSize: 0,
                                      maximumPacketSize: self.maximumPacketSize) // The initial outbound window size is presumed to be 0 until we're told otherwise.

        self.channels[channelID] = channel
        return channel
    }

    private func existingChannel(localID: UInt32) throws -> SSHChildChannel? {
        if let channel = self.channels[localID] {
            return channel
        } else if self.erroredChannels.contains(localID) {
            return nil
        } else {
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Unexpected request with local channel id \(localID)")
        }
    }
}

/// An internal protocol to encapsulate the object that owns the multiplexer.
protocol SSHMultiplexerDelegate {
    var channel: Channel? { get }

    func writeFromChildChannel(_: SSHMessage, _: EventLoopPromise<Void>?)

    func flushFromChildChannel()
}
