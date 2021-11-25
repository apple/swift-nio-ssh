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
    /// The state of a state machine that hasn't done any work yet.
    struct IdleState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet serializer used by this state machine.
        internal var serializer: SSHPacketSerializer

        internal var protectionSchemes: [NIOSSHTransportProtection.Type]
        
        internal var keyExchangeAlgorithms: [NIOSSHKeyExchangeAlgorithmProtocol.Type]

        init(role: SSHConnectionRole) {
            self.role = role
            self.serializer = SSHPacketSerializer()
            self.protectionSchemes = role.transportProtectionSchemes
            self.keyExchangeAlgorithms = role.keyExchangeAlgorithms
        }
    }
}
