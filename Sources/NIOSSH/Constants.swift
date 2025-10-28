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

public enum Constants: Sendable {
    static let version = "SSH-2.0-SwiftNIOSSH_1.0"

    public static let bundledTransportProtectionSchemes: [(NIOSSHTransportProtection & _NIOSSHSendableMetatype).Type] =
        [
            AES256GCMOpenSSHTransportProtection.self, AES128GCMOpenSSHTransportProtection.self,
        ]
}
