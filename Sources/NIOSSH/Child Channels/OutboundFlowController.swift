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

/// Keeps track of whether or not a `Channel` should be able to write based on flow control windows.
struct OutboundFlowController {
    /// The current free space in the window.
    internal private(set) var freeWindowSpace: UInt32

    /// The number of bytes currently buffered, not sent to the network.
    internal private(set) var bufferedBytes: UInt

    /// Whether the `Channel` should consider itself writable or not.
    internal var isWritable: Bool {
        UInt(self.freeWindowSpace) > self.bufferedBytes
    }

    internal init(initialWindowSize: UInt32) {
        self.freeWindowSpace = initialWindowSize
        self.bufferedBytes = 0
    }
}

extension OutboundFlowController {
    /// Notifies the flow controller that we have buffered some bytes to send to the network.
    mutating func bufferedBytes(_ bufferedBytes: Int) {
        self.bufferedBytes += UInt(bufferedBytes)
    }

    /// Notifies the flow controller that we have successfully written some bytes to the network.
    mutating func wroteBytes(_ writtenBytes: Int) {
        self.bufferedBytes -= UInt(writtenBytes)
        self.freeWindowSpace -= UInt32(writtenBytes)
    }

    mutating func outboundWindowIncremented(_ increment: UInt32) throws {
        let (newWindowSpace, overflow) = self.freeWindowSpace.addingReportingOverflow(increment)
        if overflow {
            throw NIOSSHError.protocolViolation(protocolName: "channel", violation: "Peer incremented flow control window past UInt32.max")
        }
        self.freeWindowSpace = newWindowSpace
    }
}

extension OutboundFlowController: Hashable {}

extension OutboundFlowController: CustomDebugStringConvertible {
    var debugDescription: String {
        "OutboundFlowController(freeWindowSpace: \(self.freeWindowSpace), bufferedBytes: \(self.bufferedBytes), isWritable: \(self.isWritable))"
    }
}
