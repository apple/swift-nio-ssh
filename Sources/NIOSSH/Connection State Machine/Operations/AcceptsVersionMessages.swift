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

protocol AcceptsVersionMessages {}

extension AcceptsVersionMessages {
    func receiveVersionMessage(_ version: String) throws {
        try self.validateVersion(version)
    }

    private func validateVersion(_ version: String) throws {
        guard version.count > 7, version.hasPrefix("SSH-") else {
            throw NIOSSHError.unsupportedVersion(version)
        }
        let start = version.index(version.startIndex, offsetBy: 4)
        let end = version.index(start, offsetBy: 3)
        guard version[start ..< end] == "2.0" else {
            throw NIOSSHError.unsupportedVersion(version)
        }
    }
}
