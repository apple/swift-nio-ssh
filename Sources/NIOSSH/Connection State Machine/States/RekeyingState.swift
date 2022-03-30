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
    /// The state of a state machine that is actively engaged in a key exchange operation having been active before.
    struct RekeyingState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet parser.
        var parser: SSHPacketParser

        /// The packet serializer used by this state machine.
        var serializer: SSHPacketSerializer

        var remoteVersion: String

        var protectionSchemes: [NIOSSHTransportProtection.Type]

        var sessionIdentifier: ByteBuffer

        /// The backing state machine.
        var keyExchangeStateMachine: SSHKeyExchangeStateMachine

        init(_ previousState: ReceivedKexInitWhenActiveState) {
            self.role = previousState.role
            self.parser = previousState.parser
            self.serializer = previousState.serializer
            self.remoteVersion = previousState.remoteVersion
            self.protectionSchemes = previousState.protectionSchemes
            self.sessionIdentifier = previousState.sessionIdentifier
            self.keyExchangeStateMachine = previousState.keyExchangeStateMachine
        }

        init(_ previousState: SentKexInitWhenActiveState) {
            self.role = previousState.role
            self.parser = previousState.parser
            self.serializer = previousState.serializer
            self.remoteVersion = previousState.remoteVersion
            self.protectionSchemes = previousState.protectionSchemes
            self.sessionIdentifier = previousState.sessionIdentitifier
            self.keyExchangeStateMachine = previousState.keyExchangeStateMachine
        }
    }
}

extension SSHConnectionStateMachine.RekeyingState: AcceptsKeyExchangeMessages {}

extension SSHConnectionStateMachine.RekeyingState: SendsKeyExchangeMessages {}
