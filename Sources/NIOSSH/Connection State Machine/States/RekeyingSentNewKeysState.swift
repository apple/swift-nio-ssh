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
    /// The state of a state machine that has sent new keys after a key exchange operation from an active channel,
    /// but has not yet received the new keys from the peer.
    struct RekeyingSentNewKeysState {
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

        init(_ previousState: RekeyingState) {
            self.role = previousState.role
            self.parser = previousState.parser
            self.serializer = previousState.serializer
            self.remoteVersion = previousState.remoteVersion
            self.protectionSchemes = previousState.protectionSchemes
            self.sessionIdentifier = previousState.sessionIdentifier
            self.keyExchangeStateMachine = previousState.keyExchangeStateMachine
        }
    }
}

extension SSHConnectionStateMachine.RekeyingSentNewKeysState: AcceptsKeyExchangeMessages {}

extension SSHConnectionStateMachine.RekeyingSentNewKeysState: SendsChannelMessages {}
