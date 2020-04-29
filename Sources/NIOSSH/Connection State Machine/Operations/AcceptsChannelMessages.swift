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
    mutating func receiveChannelOpen(_: SSHMessage.ChannelOpenMessage) throws {}

    mutating func receiveChannelOpenConfirmation(_: SSHMessage.ChannelOpenConfirmationMessage) throws {}

    mutating func receiveChannelOpenFailure(_: SSHMessage.ChannelOpenFailureMessage) throws {}

    mutating func receiveChannelEOF(_: SSHMessage.ChannelEOFMessage) throws {}

    mutating func receiveChannelClose(_: SSHMessage.ChannelCloseMessage) throws {}

    mutating func receiveChannelWindowAdjust(_: SSHMessage.ChannelWindowAdjustMessage) throws {}

    mutating func receiveChannelData(_: SSHMessage.ChannelDataMessage) throws {}

    mutating func receiveChannelExtendedData(_: SSHMessage.ChannelExtendedDataMessage) throws {}

    mutating func receiveChannelRequest(_: SSHMessage.ChannelRequestMessage) throws {}

    mutating func receiveChannelSuccess(_: SSHMessage.ChannelSuccessMessage) throws {}

    mutating func receiveChannelFailure(_: SSHMessage.ChannelFailureMessage) throws {}

    mutating func receiveGlobalRequest(_: SSHMessage.GlobalRequestMessage) throws {}

    mutating func receiveRequestSuccess(_: SSHMessage.RequestSuccessMessage) throws {}

    mutating func receiveRequestFailure() throws {}
}
