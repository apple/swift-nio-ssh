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

    func serialize(context: ChannelHandlerContext, message: SSHMessage) -> ByteBuffer {
        switch self.state {
        case .initialized:
            switch message {
            case .version(let version):
                var buffer = context.channel.allocator.buffer(capacity: version.count)
                buffer.writeString(version)
                return buffer
            default:
                preconditionFailure("only .version message is allowed at this point")
            }
        default:
            let messageLength = message.length
            let packetLength = messageLength + 4 + 1

            var buffer = context.channel.allocator.buffer(capacity: 1)

            return buffer
        }
    }
    
}
