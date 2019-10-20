//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO

struct SSHPacketSerializer {
    enum State {
        case initialized
        case cleartext
        case encrypted
    }

    var state: State = .initialized
    var padding: Int = 8

    func serialize(message: SSHMessage, to buffer: inout ByteBuffer) {
        switch self.state {
        case .initialized:
            switch message {
            case .version:
                buffer.writeSSHMessage(message)
            default:
                preconditionFailure("only .version message is allowed at this point")
            }
        case .cleartext:
            let index = buffer.writerIndex

            /// payload
            buffer.moveWriterIndex(forwardBy: 5)
            let messageLength = buffer.writeSSHMessage(message)

            /// RFC 4253 § 6:
            /// random padding
            ///   Arbitrary-length padding, such that the total length of (packet_length || padding_length || payload || random padding)
            ///   is a multiple of the cipher block size or 8, whichever is larger.  There MUST be at least four bytes of padding.  The
            ///   padding SHOULD consist of random bytes.  The maximum amount of padding is 255 bytes.
            let blockSize = 8
            let paddingLength = 3 + blockSize - ((messageLength + blockSize) % blockSize)

            /// packet_length
            ///   The length of the packet in bytes, not including 'mac' or the 'packet_length' field itself.
            buffer.setInteger(UInt32(1 + messageLength + paddingLength), at: index)
            /// padding_length
            buffer.setInteger(UInt8(paddingLength), at: index + 4)
            /// random padding
            buffer.writeSSHPaddingBytes(count: paddingLength)
        case .encrypted:
            preconditionFailure("Not implemented")
        }
    }
}
