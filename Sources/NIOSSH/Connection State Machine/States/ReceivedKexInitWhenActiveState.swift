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

extension SSHConnectionStateMachine {
    /// The state of a state machine that has received a KeyExchangeInit message after
    /// having been active. In this state, no further channel messages may be sent by the
    /// remote peer until key exchange is done. We can send channel messages _and_ key exchange init.
    struct ReceivedKexInitWhenActiveState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet serializer used by this state machine.
        internal var serializer: SSHPacketSerializer

        internal var parser: SSHPacketParser

        internal var remoteVersion: String

        internal var keyExchangeStateMachine: SSHKeyExchangeStateMachine

        internal var sessionIdentifier: ByteBuffer

        init(_ previous: ActiveState, allocator: ByteBufferAllocator, loop: EventLoop) {
            self.role = previous.role
            self.serializer = previous.serializer
            self.parser = previous.parser
            self.remoteVersion = previous.remoteVersion
            self.sessionIdentifier = previous.sessionIdentifier
            self.keyExchangeStateMachine = SSHKeyExchangeStateMachine(allocator: allocator, loop: loop, role: previous.role, remoteVersion: previous.remoteVersion, keyExchangeAlgorithms: self.role.keyExchangeAlgorithms, transportProtectionSchemes: self.role.transportProtectionSchemes, previousSessionIdentifier: self.sessionIdentifier)
        }
    }
}

extension SSHConnectionStateMachine.ReceivedKexInitWhenActiveState: AcceptsKeyExchangeMessages {}

extension SSHConnectionStateMachine.ReceivedKexInitWhenActiveState: SendsChannelMessages {}

extension SSHConnectionStateMachine.ReceivedKexInitWhenActiveState: SendsKeyExchangeMessages {}
