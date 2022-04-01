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
    /// The state of a state machine that has sent its version header.
    struct SentVersionState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet parser.
        var parser: SSHPacketParser

        /// The packet serializer used by this state machine.
        var serializer: SSHPacketSerializer

        var protectionSchemes: [NIOSSHTransportProtection.Type]

        private let allocator: ByteBufferAllocator

        init(idleState state: IdleState, allocator: ByteBufferAllocator, maximumPacketSize: Int) {
            self.role = state.role
            self.serializer = state.serializer
            self.protectionSchemes = state.protectionSchemes

            self.parser = SSHPacketParser(allocator: allocator, maximumPacketSize: maximumPacketSize)
            self.allocator = allocator
        }
    }
}

extension SSHConnectionStateMachine.SentVersionState: AcceptsVersionMessages {}
