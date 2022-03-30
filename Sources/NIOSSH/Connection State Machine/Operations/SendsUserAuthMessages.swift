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

protocol SendsUserAuthMessages {
    var userAuthStateMachine: UserAuthenticationStateMachine { get set }

    var serializer: SSHPacketSerializer { get set }
}

extension SendsUserAuthMessages {
    mutating func writeServiceRequest(_ message: SSHMessage.ServiceRequestMessage, into buffer: inout ByteBuffer) throws {
        self.userAuthStateMachine.sendServiceRequest(message)
        try self.serializer.serialize(message: .serviceRequest(message), to: &buffer)
    }

    mutating func writeServiceAccept(_ message: SSHMessage.ServiceAcceptMessage, into buffer: inout ByteBuffer) throws {
        self.userAuthStateMachine.sendServiceAccept(message)
        try self.serializer.serialize(message: .serviceAccept(message), to: &buffer)
    }

    mutating func writeUserAuthRequest(_ message: SSHMessage.UserAuthRequestMessage, into buffer: inout ByteBuffer) throws {
        self.userAuthStateMachine.sendUserAuthRequest(message)
        try self.serializer.serialize(message: .userAuthRequest(message), to: &buffer)
    }

    mutating func writeUserAuthSuccess(into buffer: inout ByteBuffer) throws {
        self.userAuthStateMachine.sendUserAuthSuccess()
        try self.serializer.serialize(message: .userAuthSuccess, to: &buffer)
    }

    mutating func writeUserAuthFailure(_ message: SSHMessage.UserAuthFailureMessage, into buffer: inout ByteBuffer) throws {
        self.userAuthStateMachine.sendUserAuthFailure(message)
        try self.serializer.serialize(message: .userAuthFailure(message), to: &buffer)
    }

    mutating func writeUserAuthBanner(_ message: SSHMessage.UserAuthBannerMessage, into buffer: inout ByteBuffer) throws {
        self.userAuthStateMachine.sendUserAuthBanner(message)
        try self.serializer.serialize(message: .userAuthBanner(message), to: &buffer)
    }

    mutating func writeUserAuthPKOK(_ message: SSHMessage.UserAuthPKOKMessage, into buffer: inout ByteBuffer) throws {
        self.userAuthStateMachine.sendUserAuthPKOK(message)
        try self.serializer.serialize(message: .userAuthPKOK(message), to: &buffer)
    }
}
