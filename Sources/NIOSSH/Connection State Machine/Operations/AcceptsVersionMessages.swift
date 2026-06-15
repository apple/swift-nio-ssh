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
    func receiveVersionMessage(_ banner: String) throws {
        guard try self.validateVersion(Substring(banner).utf8) else {
            throw NIOSSHError.protocolViolation(
                protocolName: "version exchange",
                violation: "version string not found"
            )
        }
    }

    private func validateVersion(_ version: Substring.UTF8View) throws -> Bool {
        if version.count > 7, version.starts(with: "SSH-".utf8) {
            let start = version.index(version.startIndex, offsetBy: 4)
            let end = version.index(start, offsetBy: 3)
            guard version[start..<end].elementsEqual(Substring("2.0").utf8) else {
                throw NIOSSHError.unsupportedVersion(String(decoding: version, as: UTF8.self))
            }
            return true
        }
        return false
    }
}
