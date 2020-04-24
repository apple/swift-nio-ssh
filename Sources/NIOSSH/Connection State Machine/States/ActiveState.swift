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

extension SSHConnectionStateMachine {
    /// The state of a state machine that has completed user auth and key exchange and is
    /// doing real work.
    struct ActiveState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet serializer used by this state machine.
        internal var serializer: SSHPacketSerializer

        internal var parser: SSHPacketParser

        init(_ previous: UserAuthenticationState) {
            self.role = previous.role
            self.serializer = previous.serializer
            self.parser = previous.parser
        }
    }
}

extension SSHConnectionStateMachine.ActiveState: AcceptsChannelMessages {}

extension SSHConnectionStateMachine.ActiveState: SendsChannelMessages {}
