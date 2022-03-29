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
    /// The state of a state machine that has receoved new keys after a key exchange operation,
    /// but has not yet sent its new keys to the peer.
    struct ReceivedNewKeysState {
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

        /// The user auth state machine that drives user authentication.
        var userAuthStateMachine: UserAuthenticationStateMachine

        init(keyExchangeState state: KeyExchangeState,
             loop: EventLoop) {
            self.role = state.role
            self.parser = state.parser
            self.serializer = state.serializer
            self.remoteVersion = state.remoteVersion
            self.protectionSchemes = state.protectionSchemes
            self.keyExchangeStateMachine = state.keyExchangeStateMachine

            // We force unwrap the session ID because it's programmer error to not have it at this time.
            self.sessionIdentifier = state.keyExchangeStateMachine.sessionID!
            self.userAuthStateMachine = UserAuthenticationStateMachine(role: self.role,
                                                                       loop: loop,
                                                                       sessionID: self.sessionIdentifier)
        }
    }
}

extension SSHConnectionStateMachine.ReceivedNewKeysState: SendsKeyExchangeMessages {}

extension SSHConnectionStateMachine.ReceivedNewKeysState: AcceptsUserAuthMessages {}
