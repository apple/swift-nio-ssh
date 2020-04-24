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

struct ChildChannelWindowManager {
    private(set) var targetWindowSize: UInt32

    private var bufferedBytes: UInt32

    private var currentWindowSize: UInt32

    init(targetWindowSize: UInt32) {
        self.targetWindowSize = targetWindowSize
        self.bufferedBytes = 0
        self.currentWindowSize = targetWindowSize
    }
}

extension ChildChannelWindowManager {
    mutating func bufferFlowControlledBytes(_ bufferedBytes: Int) throws {
        let increment = UInt32(bufferedBytes)

        let (newBufferedBytes, bufferedOverflow) = self.bufferedBytes.addingReportingOverflow(increment)
        let (newWindowSize, windowSizeOverflow) = self.currentWindowSize.subtractingReportingOverflow(increment)

        // Whoops, the window size went out of band! This is an error caused by the remote peer.
        if windowSizeOverflow || bufferedOverflow {
            throw NIOSSHError.flowControlViolation(currentWindow: self.currentWindowSize, increment: increment)
        }

        self.bufferedBytes = newBufferedBytes
        self.currentWindowSize = newWindowSize
    }

    mutating func unbufferBytes(_ bytes: Int) -> Increment? {
        let bytes = UInt32(bytes)

        self.bufferedBytes -= bytes

        // Ok, we want to check whether we need to build an increment.
        // To do it, we check what the current "available" window is, where
        // the "available" window is the window the remote peer still has plus
        // the bytes we haven't delivered to the user yet (as we don't want to
        // give those bytes back to the remote peer). There are three cases:
        //
        // 1. The available window is larger than the target. Do nothing.
        // 2. The available window is larger than half the target. Do nothing.
        // 3. The available window is smaller than half the target. Emit an increment.
        let availableWindow = self.currentWindowSize + self.bufferedBytes
        assert(availableWindow <= self.targetWindowSize)

        if availableWindow > (self.targetWindowSize / 2) {
            return nil
        } else {
            let increment = self.targetWindowSize - availableWindow
            self.currentWindowSize += increment
            return Increment(rawValue: increment)
        }
    }
}

extension ChildChannelWindowManager {
    struct Increment {
        var rawValue: UInt32

        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
    }
}

extension ChildChannelWindowManager.Increment: Hashable {}

extension ChildChannelWindowManager.Increment: RawRepresentable {}

extension UInt32 {
    init(_ increment: ChildChannelWindowManager.Increment) {
        self = increment.rawValue
    }
}
