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

protocol SendsKeyExchangeMessages {
    var keyExchangeStateMachine: SSHKeyExchangeStateMachine { get set }

    var serializer: SSHPacketSerializer { get set }
}

extension SendsKeyExchangeMessages {
    mutating func writeKeyExchangeMessage(_ message: SSHMessage.KeyExchangeMessage, into buffer: inout ByteBuffer) throws {
        self.keyExchangeStateMachine.send(keyExchange: message)
        try self.serializer.serialize(message: .keyExchange(message), to: &buffer)
    }

    mutating func writeKeyExchangeInitMessage(_ message: SSHMessage.KeyExchangeECDHInitMessage, into buffer: inout ByteBuffer) throws {
        self.keyExchangeStateMachine.send(keyExchangeInit: message)
        try self.serializer.serialize(message: .keyExchangeInit(message), to: &buffer)
    }

    mutating func writeKeyExchangeReplyMessage(_ message: SSHMessage.KeyExchangeECDHReplyMessage, into buffer: inout ByteBuffer) throws {
        try self.keyExchangeStateMachine.send(keyExchangeReply: message)
        try self.serializer.serialize(message: .keyExchangeReply(message), to: &buffer)
    }

    mutating func writeNewKeysMessage(into buffer: inout ByteBuffer) throws {
        let result = self.keyExchangeStateMachine.sendNewKeys()
        try self.serializer.serialize(message: .newKeys, to: &buffer)
        self.serializer.addEncryption(result)
    }
}
