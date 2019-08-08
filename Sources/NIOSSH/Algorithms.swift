//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO

extension ByteBuffer {
    

    mutating func readKeyAuthenticationAlgorithms() -> [Substring]? {
        guard var string = self.readSSHString() else {
            return nil
        }
        // readSSHString guarantees that we will be able to read all string bytes
        return string.readString(length: string.readableBytes)!.split(separator: ",")
    }

    mutating func readEncryptionAlgorithms() -> [Substring]? {
        guard var string = self.readSSHString() else {
            return nil
        }
        // readSSHString guarantees that we will be able to read all string bytes
        return string.readString(length: string.readableBytes)!.split(separator: ",")
    }

    mutating func readMACAlgorithms() -> [Substring]? {
        guard var string = self.readSSHString() else {
            return nil
        }
        // readSSHString guarantees that we will be able to read all string bytes
        return string.readString(length: string.readableBytes)!.split(separator: ",")
    }

    mutating func readCompressionAlgorithms() -> [Substring]? {
        guard var string = self.readSSHString() else {
            return nil
        }
        // readSSHString guarantees that we will be able to read all string bytes
        return string.readString(length: string.readableBytes)!.split(separator: ",")
    }

    mutating func readLanguages() -> [Substring]? {
        guard var string = self.readSSHString() else {
            return nil
        }
        // readSSHString guarantees that we will be able to read all string bytes
        return string.readString(length: string.readableBytes)!.split(separator: ",")
    }
}
