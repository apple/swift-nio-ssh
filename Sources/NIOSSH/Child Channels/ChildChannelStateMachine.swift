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

/// A state machine that manages the state of child channels.
///
/// Child channels move through a weird set of states, because they can "exist" before the protocol is aware of them. In particular, there
/// are a few strange states that don't correspond to what the wire protocol looks like.
struct ChildChannelStateMachine {
    private var state: State

    init(localChannelID: UInt32) {
        self.state = .idle(localChannelID: localChannelID)
    }
}

extension ChildChannelStateMachine {
    fileprivate enum State: Hashable {
        /// `idle` represents a child channel that has been allocated locally, but where we haven't asked the wire
        /// protocol to do anything with it yet: that is, we have not requested the channel. Such a channel is purely
        /// virtual. It exists only because we're attempting to start a channel locally and we haven't configured it yet.
        case idle(localChannelID: UInt32)

        /// `requestedLocally` is a channel for which we have sent a channel request, but haven't received a response yet.
        /// This channel is "active on the network" in the sense that the remote peer will come to know of its existence,
        /// but it's not yet a real channel that can perform any kind of I/O, so from the perspective of the user of the
        /// channel this channel isn't active yet.
        case requestedLocally(localChannelID: UInt32)

        /// `requestedRemotely` is a channel for which the remote peer has sent a channel request, but we have not yet
        /// responded. This channel is also "active on the network" in the sense that if our initialization fails we have
        /// to take some kind of action to kill this channel. However, this channel can't do I/O yet, so from the perspective
        /// of the user of the channel this channel isn't active yet.
        case requestedRemotely(channelID: SSHChannelIdentifier)

        /// `active` is a channel that has been both requested and accepted. Data can flow freely on this channel in both directions.
        /// We have neither sent nor received either a `CHANNEL_EOF` or a `CHANNEL_CLOSE` so all I/O is flowing appropriately.
        case active(channelID: SSHChannelIdentifier)

        /// `halfClosedLocal` is a channel where we have sent a `CHANNEL_EOF` message, but the peer has not. Such a channel is active,
        /// and on the network. The remote peer may continue to send data. We still have flow control responsibilities.
        case halfClosedLocal(channelID: SSHChannelIdentifier)

        /// `halfClosedRemote` is a channel where the remote peer has sent a `CHANNEL_EOF` message, but we have not. Such a channel is
        /// active and on the network. We may continue to send data. We must obey the remote peer flow control rules, but we do not
        /// need to issue further flow control updates to the remote peer.
        case halfClosedRemote(channelID: SSHChannelIdentifier)

        /// `quiescent` is a channel where both peers have sent `CHANNEL_EOF`, but no-one has sent `CHANNEL_CLOSE` yet. Metadata messages
        /// may still be sent, but no further data may be exchanged.
        case quiescent(channelID: SSHChannelIdentifier)

        /// `closedRemotely` is a channel where the remote peer has sent `CHANNEL_CLOSE` but we have not yet sent `CHANNEL_CLOSE` back.
        case closedRemotely(channelID: SSHChannelIdentifier, sentEOF: Bool)

        /// `closedLocally` is a channel where we have sent `CHANNEL_CLOSE` but have not yet received a `CHANNEL_CLOSE` back.
        case closedLocally(channelID: SSHChannelIdentifier, receivedPeerEOF: Bool)

        /// `closed` is a channel where we have both sent and received `CHANNEL_CLOSE`.
        /// No further activity is possible. The channel identifier may now be re-used.
        case closed(channelID: SSHChannelIdentifier)
    }
}

// MARK: Receiving frames

extension ChildChannelStateMachine {
    mutating func receiveChannelOpen(_ message: SSHMessage.ChannelOpenMessage) {
        // The channel open message is a request to open the channel. Receiving one means this child channel is on the server side,
        // and this is a remotely-initiated channel.
        switch self.state {
        case .idle(localChannelID: let localID):
            self.state = .requestedRemotely(channelID: SSHChannelIdentifier(localChannelID: localID, peerChannelID: message.senderChannel))

        case .requestedLocally:
            // We precondition here because the rest of the code should prevent this from happening: there's no way to deliver a
            // channel open request for a channel we requested, because the message cannot carry our channel ID.
            preconditionFailure("Somehow received an open request for a locally-initiated channel")

        case .requestedRemotely, .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedRemotely, .closedLocally, .closed:
            // As above, we precondition here because the rest of the code should prevent this from happening: there's no way to deliver
            // a channel open request for a channel that has a remote ID already!
            preconditionFailure("Received an open request for an active channel")
        }
    }

    mutating func receiveChannelOpenConfirmation(_ message: SSHMessage.ChannelOpenConfirmationMessage) throws {
        // Channel open confirmation is sent in response to us having requested an open channel.
        switch self.state {
        case .requestedLocally(localChannelID: let localID):
            precondition(message.recipientChannel == localID)
            self.state = .active(channelID: SSHChannelIdentifier(localChannelID: localID, peerChannelID: message.senderChannel))

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Open confirmation sent on idle channel")

        case .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Open confirmation sent on remotely-initiated channel")

        case .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Duplicate open confirmation received.")
        }
    }

    mutating func receiveChannelOpenFailure(_ message: SSHMessage.ChannelOpenFailureMessage) throws {
        // Channel open failure is sent in response to us having requested an open channel. This is an immediate
        // transition to closed.
        switch self.state {
        case .requestedLocally(localChannelID: let localID):
            precondition(message.recipientChannel == localID)
            self.state = .closed(channelID: SSHChannelIdentifier(localChannelID: localID, peerChannelID: 0))

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Open failure sent on idle channel")

        case .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Open failure sent on remotely-initiated channel")

        case .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Duplicate open failure received.")
        }
    }

    mutating func receiveChannelEOF(_ message: SSHMessage.ChannelEOFMessage) throws {
        // We can get channelEOF at any point after the channel is active.
        switch self.state {
        case .active(channelID: let channelID):
            precondition(message.recipientChannel == channelID.localChannelID)
            self.state = .halfClosedRemote(channelID: channelID)

        case .halfClosedLocal(channelID: let channelID):
            precondition(message.recipientChannel == channelID.localChannelID)
            self.state = .quiescent(channelID: channelID)

        case .closedLocally(channelID: let channelID, receivedPeerEOF: false):
            precondition(message.recipientChannel == channelID.localChannelID)
            self.state = .closedLocally(channelID: channelID, receivedPeerEOF: true)

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received EOF on idle")

        case .requestedLocally, .requestedRemotely, .halfClosedRemote, .quiescent, .closedLocally(channelID: _, receivedPeerEOF: true), .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received EOF out of sequence.")
        }
    }

    mutating func receiveChannelClose(_ message: SSHMessage.ChannelCloseMessage) throws {
        // We can get channel close at any point after the channel is active.
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID):
            precondition(message.recipientChannel == channelID.localChannelID)
            self.state = .closedRemotely(channelID: channelID, sentEOF: false)

        case .halfClosedLocal(channelID: let channelID),
             .quiescent(channelID: let channelID):
            precondition(message.recipientChannel == channelID.localChannelID)
            self.state = .closedRemotely(channelID: channelID, sentEOF: true)

        case .closedLocally(channelID: let channelID, receivedPeerEOF: _):
            precondition(message.recipientChannel == channelID.localChannelID)
            self.state = .closed(channelID: channelID)

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received close on idle")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received close before channel was open.")

        case .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received close on closed channel.")
        }
    }

    mutating func receiveChannelWindowAdjust(_ message: SSHMessage.ChannelWindowAdjustMessage) throws {
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID),
             .closedLocally(channelID: let channelID, receivedPeerEOF: _):
            precondition(message.recipientChannel == channelID.localChannelID)

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel window adjust on idle")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel window adjust before channel was open.")

        case .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received window adjust on closed channel.")
        }
    }

    mutating func receiveChannelData(_ message: SSHMessage.ChannelDataMessage) throws {
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .closedLocally(channelID: let channelID, receivedPeerEOF: false):
            // We allow data in closed locally because there may be a timing problem here.
            precondition(message.recipientChannel == channelID.localChannelID)

        case .halfClosedRemote, .quiescent, .closedLocally(channelID: _, receivedPeerEOF: true):
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received message after EOF.")

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel EOF on idle")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel data before channel was open.")

        case .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received data on closed channel.")
        }
    }

    mutating func receiveChannelExtendedData(_ message: SSHMessage.ChannelExtendedDataMessage) throws {
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .closedLocally(channelID: let channelID, receivedPeerEOF: false):
            // We allow data in closed locally because there may be a timing problem here.
            precondition(message.recipientChannel == channelID.localChannelID)

        case .halfClosedRemote, .quiescent, .closedLocally(channelID: _, receivedPeerEOF: true):
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received message after EOF.")

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel extended data on idle")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel extended data before channel was open.")

        case .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received extended data on closed channel.")
        }
    }

    mutating func receiveChannelRequest(_ message: SSHMessage.ChannelRequestMessage) throws {
        // We can get channel request at any point after the channel is active.
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID),
             .closedLocally(channelID: let channelID, receivedPeerEOF: _):
            precondition(message.recipientChannel == channelID.localChannelID)

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel request on idle")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel request before channel was open.")

        case .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel request on closed channel.")
        }
    }

    mutating func receiveChannelSuccess(_ message: SSHMessage.ChannelSuccessMessage) throws {
        // We can get channel success at any point after the channel is active.
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID),
             .closedLocally(channelID: let channelID, receivedPeerEOF: _):
            precondition(message.recipientChannel == channelID.localChannelID)

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel success on idle")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel success before channel was open.")

        case .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel success on closed channel.")
        }
    }

    mutating func receiveChannelFailure(_ message: SSHMessage.ChannelFailureMessage) throws {
        // We can get channel failure at any point after the channel is active.
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID),
             .closedLocally(channelID: let channelID, receivedPeerEOF: _):
            precondition(message.recipientChannel == channelID.localChannelID)

        case .idle:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel failure on idle")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel failure before channel was open.")

        case .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Received channel failure on closed channel.")
        }
    }
}

// MARK: Sending frames

extension ChildChannelStateMachine {
    mutating func sendChannelOpen(_ message: SSHMessage.ChannelOpenMessage) {
        // The channel open message is a request to open the channel. Sending one means this child channel is on the client side,
        // and this is a locally-initiated channel.
        switch self.state {
        case .idle(localChannelID: let localID):
            precondition(localID == message.senderChannel)
            self.state = .requestedLocally(localChannelID: localID)

        case .requestedLocally, .requestedRemotely, .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely, .closed:
            // The code should prevent us from sending channel open twice.
            preconditionFailure("Attempted to send duplicate channel open")
        }
    }

    mutating func sendChannelOpenConfirmation(_ message: SSHMessage.ChannelOpenConfirmationMessage) {
        // Channel open confirmation is sent by us in response to the peer having requested an open channel.
        switch self.state {
        case .requestedRemotely(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)
            precondition(message.senderChannel == channelID.localChannelID)
            self.state = .active(channelID: channelID)

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow received open confirmation for idle channel")

        case .requestedLocally:
            preconditionFailure("Sent open confirmation on locally initiated channel.")

        case .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely, .closed:
            preconditionFailure("Duplicate open confirmation sent.")
        }
    }

    mutating func sendChannelOpenFailure(_ message: SSHMessage.ChannelOpenFailureMessage) {
        // Channel open failure is sent in response to the peer having requested an open channel. This is an immediate
        // transition to closed.
        switch self.state {
        case .requestedRemotely(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)
            self.state = .closed(channelID: channelID)

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow received open confirmation for idle channel")

        case .requestedLocally:
            preconditionFailure("Sent open failure on locally initiated channel.")

        case .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely, .closed:
            preconditionFailure("Duplicate open failure sent.")
        }
    }

    mutating func sendChannelEOF(_ message: SSHMessage.ChannelEOFMessage) throws {
        // We can send channelEOF at any point after the channel is active, so long as we don't send it twice.
        switch self.state {
        case .active(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)
            self.state = .halfClosedLocal(channelID: channelID)

        case .halfClosedLocal(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)
            self.state = .quiescent(channelID: channelID)

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow sent channel EOF for idle channel")

        case .requestedLocally, .requestedRemotely, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent EOF out of sequence.")
        }
    }

    mutating func sendChannelClose(_ message: SSHMessage.ChannelCloseMessage) throws {
        // We can send channel close at any point after the channel is active.
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)
            self.state = .closedLocally(channelID: channelID, receivedPeerEOF: false)

        case .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)
            self.state = .closedLocally(channelID: channelID, receivedPeerEOF: true)

        case .closedRemotely(channelID: let channelID, sentEOF: _):
            precondition(message.recipientChannel == channelID.peerChannelID)
            self.state = .closed(channelID: channelID)

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow received channel EOF for idle channel")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent close before channel was open.")

        case .closedLocally, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent close on closed channel.")
        }
    }

    mutating func sendChannelWindowAdjust(_ message: SSHMessage.ChannelWindowAdjustMessage) throws {
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow received channel EOF for idle channel")

        case .requestedLocally, .requestedRemotely, .closedLocally, .closedRemotely, .closed:
            preconditionFailure("Sent channel window adjust on channel in invalid state")
        }
    }

    mutating func sendChannelData(_ message: SSHMessage.ChannelDataMessage) throws {
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)

        case .halfClosedLocal, .quiescent:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent message after EOF.")

        case .closedLocally, .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent data on closed channel.")

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow received channel EOF for idle channel")

        case .requestedLocally, .requestedRemotely:
            preconditionFailure("Sent data before channel active")
        }
    }

    mutating func sendChannelExtendedData(_ message: SSHMessage.ChannelExtendedDataMessage) throws {
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)

        case .halfClosedLocal, .quiescent:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent message after EOF.")

        case .closedLocally, .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent extended data on closed channel.")

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow received channel EOF for idle channel")

        case .requestedLocally, .requestedRemotely:
            preconditionFailure("Sent extended data before channel active")
        }
    }

    mutating func sendChannelRequest(_ message: SSHMessage.ChannelRequestMessage) throws {
        // We can send channel request at any point after the channel is active.
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow sent channel request for idle channel")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent channel request before channel was open.")

        case .closedLocally, .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent channel request on closed channel.")
        }
    }

    mutating func sendChannelSuccess(_ message: SSHMessage.ChannelSuccessMessage) throws {
        // We can send channel success at any point after the channel is active.
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow sent channel success for idle channel")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent channel success before channel was open.")

        case .closedLocally, .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent channel success on closed channel.")
        }
    }

    mutating func sendChannelFailure(_ message: SSHMessage.ChannelFailureMessage) throws {
        // We can send channel failure at any point after the channel is active.
        switch self.state {
        case .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID):
            precondition(message.recipientChannel == channelID.peerChannelID)

        case .idle:
            // In the idle state we haven't either sent a channel open or received one. This is not really possible.
            preconditionFailure("Somehow sent channel success for idle channel")

        case .requestedLocally, .requestedRemotely:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent channel failure before channel was open.")

        case .closedLocally, .closedRemotely, .closed:
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Sent channel failure on closed channel.")
        }
    }
}

// MARK: Other state changes

extension ChildChannelStateMachine {
    /// Called when TCP EOF is received. This forcibly shuts down the channel from any state.
    ///
    /// Must not be called on closed channels.
    mutating func receiveTCPEOF() {
        switch self.state {
        case .closed:
            preconditionFailure("Channel already closed")

        case .idle(localChannelID: let localID),
             .requestedLocally(localChannelID: let localID):
            self.state = .closed(channelID: SSHChannelIdentifier(localChannelID: localID, peerChannelID: 0))

        case .requestedRemotely(channelID: let channelID),
             .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID),
             .closedLocally(channelID: let channelID, receivedPeerEOF: _),
             .closedRemotely(channelID: let channelID, sentEOF: _):
            self.state = .closed(channelID: channelID)
        }
    }
}

// MARK: Helper computed properties

extension ChildChannelStateMachine {
    /// Whether this channel is currently active on the network.
    var isActiveOnNetwork: Bool {
        switch self.state {
        case .idle, .closed:
            return false
        case .requestedLocally, .requestedRemotely, .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely:
            return true
        }
    }

    /// Whether this channel is closed.
    var isClosed: Bool {
        switch self.state {
        case .closed:
            return true
        case .idle, .requestedLocally, .requestedRemotely, .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely:
            return false
        }
    }

    /// Whether `Channel.isActive` should be true.
    var isActiveOnChannel: Bool {
        switch self.state {
        case .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely:
            return true
        case .idle, .requestedLocally, .requestedRemotely, .closed:
            return false
        }
    }

    // Whether we've sent a channel close message.
    var sentClose: Bool {
        switch self.state {
        case .closedLocally, .closed:
            return true
        case .idle, .requestedLocally, .requestedRemotely, .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedRemotely:
            return false
        }
    }

    /// The local identifier for this channel. We always know this identifier.
    var localChannelIdentifier: UInt32 {
        switch self.state {
        case .idle(localChannelID: let localID),
             .requestedLocally(localChannelID: let localID):
            return localID

        case .requestedRemotely(channelID: let channelID),
             .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID),
             .closedRemotely(channelID: let channelID, sentEOF: _),
             .closedLocally(channelID: let channelID, receivedPeerEOF: _),
             .closed(channelID: let channelID):
            return channelID.localChannelID
        }
    }

    // The remote identifier for this channel. We only know this when the remote peer has told us.
    var remoteChannelIdentifier: UInt32? {
        switch self.state {
        case .idle, .requestedLocally:
            return nil

        case .requestedRemotely(channelID: let channelID),
             .active(channelID: let channelID),
             .halfClosedLocal(channelID: let channelID),
             .halfClosedRemote(channelID: let channelID),
             .quiescent(channelID: let channelID),
             .closedRemotely(channelID: let channelID, sentEOF: _),
             .closedLocally(channelID: let channelID, receivedPeerEOF: _),
             .closed(channelID: let channelID):
            return channelID.peerChannelID
        }
    }

    var sentEOF: Bool {
        switch self.state {
        case .halfClosedLocal, .quiescent, .closedLocally, .closedRemotely(channelID: _, sentEOF: true), .closed:
            return true

        case .idle, .requestedLocally, .requestedRemotely, .active, .halfClosedRemote, .closedRemotely(channelID: _, sentEOF: false):
            return false
        }
    }

    // Whether we have activated yet.
    var awaitingActivation: Bool {
        switch self.state {
        case .idle, .requestedLocally, .requestedRemotely:
            return true

        case .active, .halfClosedLocal, .halfClosedRemote, .quiescent, .closedLocally, .closedRemotely, .closed:
            return false
        }
    }
}

extension ChildChannelStateMachine {
    /// An action to take in response to a specific operation.
    enum Action {
        /// Ignore this message: do nothing.
        case ignore

        /// The message should be processed as normal.
        case process
    }
}
