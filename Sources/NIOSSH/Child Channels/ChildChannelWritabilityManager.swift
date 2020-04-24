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

/// The outbound flow control manager for `SSHChildChannel` objects.
///
/// Our flow control strategy here is in two parts. The first is a watermarked
/// pending-byte-based flow control strategy that uses the number of writes that have been
/// issued by the channel but not written to the network. If these writes move past a certain
/// threshold, the channel writability state will change.
///
/// The second is a parent-channel based observation. If the parent channel is not writable,
/// there is no reason to tell the stream channels that they can write either, as those writes
/// will simply back up in the parent.
///
/// The observed effect is that the `SSHChildChannel` is writable only if both of the above
/// strategies are writable: if either is not writable, neither is the `SSHChildChannel`.
struct ChildChannelWritabilityManager {
    private var watermarkedController: OutboundFlowController

    private var parentIsWritable: Bool

    internal init(initialWindowSize: UInt32, parentIsWritable: Bool) {
        self.watermarkedController = OutboundFlowController(initialWindowSize: initialWindowSize)
        self.parentIsWritable = parentIsWritable
    }
}

extension ChildChannelWritabilityManager {
    /// Whether the `SSHChildChannel` should be writable.
    var isWritable: Bool {
        self.watermarkedController.isWritable && self.parentIsWritable
    }

    /// The number of bytes available in the flow control window on the network.
    var windowSpaceOnNetwork: Int {
        Int(self.watermarkedController.freeWindowSpace)
    }
}

extension ChildChannelWritabilityManager {
    /// A value representing a change in writability.
    enum WritabilityChange: Hashable {
        /// No writability change occurred
        case noChange

        /// Writability changed to a new value.
        case changed(newValue: Bool)
    }
}

extension ChildChannelWritabilityManager {
    /// Notifies the flow controller that we have queued some bytes for writing to the network.
    mutating func bufferedBytes(_ bufferedBytes: Int) -> WritabilityChange {
        self.mayChangeWritability {
            $0.watermarkedController.bufferedBytes(bufferedBytes)
        }
    }

    /// Notifies the flow controller that we have successfully written some bytes to the network.
    mutating func wroteBytes(_ writtenBytes: Int) -> WritabilityChange {
        self.mayChangeWritability {
            $0.watermarkedController.wroteBytes(writtenBytes)
        }
    }

    /// Notifies the flow controller that the outbound flow control window has changed size.
    mutating func outboundWindowIncremented(_ increment: UInt32) throws -> WritabilityChange {
        try self.mayChangeWritability {
            try $0.watermarkedController.outboundWindowIncremented(increment)
        }
    }

    mutating func parentWritabilityChanged(_ newWritability: Bool) -> WritabilityChange {
        self.mayChangeWritability {
            $0.parentIsWritable = newWritability
        }
    }

    private mutating func mayChangeWritability(_ body: (inout ChildChannelWritabilityManager) throws -> Void) rethrows -> WritabilityChange {
        let wasWritable = self.isWritable
        try body(&self)
        let isWritable = self.isWritable

        if wasWritable != isWritable {
            return .changed(newValue: isWritable)
        } else {
            return .noChange
        }
    }
}

extension ChildChannelWritabilityManager: Hashable {}

extension ChildChannelWritabilityManager: CustomDebugStringConvertible {
    var debugDescription: String {
        "ChildChannelWritabilityManager(parentIsWritable: \(self.parentIsWritable), watermarkedController: \(self.watermarkedController.debugDescription))"
    }
}
