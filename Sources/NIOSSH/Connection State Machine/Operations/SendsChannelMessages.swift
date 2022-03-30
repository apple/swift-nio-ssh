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

// Right now this doesn't do that much, but we may use it in future for supporting re-keying.
protocol SendsChannelMessages {
    var serializer: SSHPacketSerializer { get set }
}

extension SendsChannelMessages {
    mutating func writeChannelOpen(_ message: SSHMessage.ChannelOpenMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelOpen(message), to: &buffer)
    }

    mutating func writeChannelOpenConfirmation(_ message: SSHMessage.ChannelOpenConfirmationMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelOpenConfirmation(message), to: &buffer)
    }

    mutating func writeChannelOpenFailure(_ message: SSHMessage.ChannelOpenFailureMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelOpenFailure(message), to: &buffer)
    }

    mutating func writeChannelEOF(_ message: SSHMessage.ChannelEOFMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelEOF(message), to: &buffer)
    }

    mutating func writeChannelClose(_ message: SSHMessage.ChannelCloseMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelClose(message), to: &buffer)
    }

    mutating func writeChannelWindowAdjust(_ message: SSHMessage.ChannelWindowAdjustMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelWindowAdjust(message), to: &buffer)
    }

    mutating func writeChannelData(_ message: SSHMessage.ChannelDataMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelData(message), to: &buffer)
    }

    mutating func writeChannelExtendedData(_ message: SSHMessage.ChannelExtendedDataMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelExtendedData(message), to: &buffer)
    }

    mutating func writeChannelRequest(_ message: SSHMessage.ChannelRequestMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelRequest(message), to: &buffer)
    }

    mutating func writeChannelSuccess(_ message: SSHMessage.ChannelSuccessMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelSuccess(message), to: &buffer)
    }

    mutating func writeChannelFailure(_ message: SSHMessage.ChannelFailureMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .channelFailure(message), to: &buffer)
    }

    mutating func writeGlobalRequest(_ message: SSHMessage.GlobalRequestMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .globalRequest(message), to: &buffer)
    }

    mutating func writeRequestSuccess(_ message: SSHMessage.RequestSuccessMessage, into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .requestSuccess(message), to: &buffer)
    }

    mutating func writeRequestFailure(into buffer: inout ByteBuffer) throws {
        try self.serializer.serialize(message: .requestFailure, to: &buffer)
    }
}
