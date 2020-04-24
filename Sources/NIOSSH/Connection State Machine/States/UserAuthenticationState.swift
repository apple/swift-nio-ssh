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

import NIO

extension SSHConnectionStateMachine {
    /// The state of a state machine that is actively engaged in a user authentication operation.
    struct UserAuthenticationState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet parser.
        var parser: SSHPacketParser

        /// The packet serializer used by this state machine.
        var serializer: SSHPacketSerializer

        /// The backing state machine.
        var userAuthStateMachine: UserAuthenticationStateMachine

        init(sentNewKeysState state: SentNewKeysState) {
            self.role = state.role
            self.parser = state.parser
            self.serializer = state.serializer
            self.userAuthStateMachine = state.userAuthStateMachine
        }

        init(receivedNewKeysState state: ReceivedNewKeysState) {
            self.role = state.role
            self.parser = state.parser
            self.serializer = state.serializer
            self.userAuthStateMachine = state.userAuthStateMachine
        }
    }
}

extension SSHConnectionStateMachine.UserAuthenticationState: AcceptsUserAuthMessages {}

extension SSHConnectionStateMachine.UserAuthenticationState: SendsUserAuthMessages {}
