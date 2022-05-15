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
    /// The state of a state machine that has sent a KeyExchangeInit message after
    /// having been active. In this state, no further channel messages may be sent by the
    /// us until key exchange is done. We can receive channel messages _and_ key exchange init.
    struct SentKexInitWhenActiveState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet serializer used by this state machine.
        internal var serializer: SSHPacketSerializer

        internal var parser: SSHPacketParser

        internal var remoteVersion: String

        internal var sessionIdentitifier: ByteBuffer

        internal var keyExchangeStateMachine: SSHKeyExchangeStateMachine

        init(_ previous: ActiveState, allocator: ByteBufferAllocator, loop: EventLoop) {
            self.role = previous.role
            self.serializer = previous.serializer
            self.parser = previous.parser
            self.remoteVersion = previous.remoteVersion
            self.sessionIdentitifier = previous.sessionIdentifier
            self.keyExchangeStateMachine = SSHKeyExchangeStateMachine(allocator: allocator, loop: loop, role: self.role, remoteVersion: self.remoteVersion, keyExchangeAlgorithms: role.keyExchangeAlgorithms, transportProtectionSchemes: role.transportProtectionSchemes, previousSessionIdentifier: previous.sessionIdentifier)
        }
    }
}

extension SSHConnectionStateMachine.SentKexInitWhenActiveState: AcceptsKeyExchangeMessages {}

extension SSHConnectionStateMachine.SentKexInitWhenActiveState: AcceptsChannelMessages {}

extension SSHConnectionStateMachine.SentKexInitWhenActiveState: SendsKeyExchangeMessages {}
