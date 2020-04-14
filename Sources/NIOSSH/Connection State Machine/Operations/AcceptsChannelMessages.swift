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

/// A protocol for states that accept channel messages.
protocol AcceptsChannelMessages {
    var parser: SSHPacketParser { get set }
}

// This protocol doesn't do much right now, but in future we might need to support re-keying, and this is a good place to hook it in.

extension AcceptsChannelMessages {
    mutating func receiveChannelOpen(_ message: SSHMessage.ChannelOpenMessage) throws {
        return
    }

    mutating func receiveChannelOpenConfirmation(_ message: SSHMessage.ChannelOpenConfirmationMessage) throws {
        return
    }

    mutating func receiveChannelOpenFailure(_ message: SSHMessage.ChannelOpenFailureMessage) throws {
        return
    }

    mutating func receiveChannelEOF(_ message: SSHMessage.ChannelEOFMessage) throws {
        return
    }

    mutating func receiveChannelClose(_ message: SSHMessage.ChannelCloseMessage) throws {
        return
    }

    mutating func receiveChannelWindowAdjust(_ message: SSHMessage.ChannelWindowAdjustMessage) throws {
        return
    }

    mutating func receiveChannelData(_ message: SSHMessage.ChannelDataMessage) throws {
        return
    }

    mutating func receiveChannelExtendedData(_ message: SSHMessage.ChannelExtendedDataMessage) throws {
        return
    }

    mutating func receiveChannelRequest(_ message: SSHMessage.ChannelRequestMessage) throws {
        return
    }

    mutating func receiveChannelSuccess(_ message: SSHMessage.ChannelSuccessMessage) throws {
        return
    }

    mutating func receiveChannelFailure(_ message: SSHMessage.ChannelFailureMessage) throws {
        return
    }

    mutating func receiveGlobalRequest(_ message: SSHMessage.GlobalRequestMessage) throws {
        return
    }
}
