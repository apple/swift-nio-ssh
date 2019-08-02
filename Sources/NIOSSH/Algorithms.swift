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

struct KeyExchangeAlgorithms: OptionSet {
    let rawValue: UInt8

    static let Curve25519SHA256 = KeyExchangeAlgorithms(rawValue: 1 << 0)
    static let ECDHSHA2NISTP521 = KeyExchangeAlgorithms(rawValue: 1 << 1)
    static let ECDHSHA2NISTP384 = KeyExchangeAlgorithms(rawValue: 1 << 2)
    static let ECDHSHA2NISTP256 = KeyExchangeAlgorithms(rawValue: 1 << 3)
}

struct KeyAuthenticationAlgorithms: OptionSet {
    let rawValue: UInt8

    static let SSHED25519 = KeyAuthenticationAlgorithms(rawValue: 1 << 0)
    static let ECDSASHA2NISTP521 = KeyAuthenticationAlgorithms(rawValue: 1 << 1)
    static let ECDSASHA2NISTP384 = KeyAuthenticationAlgorithms(rawValue: 1 << 2)
    static let ECDSASHA2NISTP256 = KeyAuthenticationAlgorithms(rawValue: 1 << 3)
}

struct EncryptionAlgorithms: OptionSet {
    let rawValue: UInt8

    static let AES256GCM = EncryptionAlgorithms(rawValue: 1 << 0)
}

struct MACAlgorithms: OptionSet {
    let rawValue: UInt8

    static let HMACSHA2256 = MACAlgorithms(rawValue: 1 << 0)
}

struct CompressionAlgorithms: OptionSet {
    let rawValue: UInt8
}

struct Languages: OptionSet {
    let rawValue: UInt8
}

extension ByteBuffer {
    mutating func readKeyExchangeAlgorithms() -> KeyExchangeAlgorithms? {
        guard var string = self.readSSHString() else {
            return nil
        }
        guard let list = string.readString(length: string.readableBytes) else {
            return []
        }
        var algorithms: KeyExchangeAlgorithms = []
        for element in list.split(separator: ",") {
            switch element {
            case "curve25519-sha256":
                algorithms.insert(.Curve25519SHA256)
            case "curve25519-sha256@libssh.org":
                algorithms.insert(.Curve25519SHA256)
            case "ecdh-sha2-nistp521":
                algorithms.insert(.ECDHSHA2NISTP521)
            case "ecdh-sha2-nistp384":
                algorithms.insert(.ECDHSHA2NISTP384)
            case "ecdh-sha2-nistp256":
                algorithms.insert(.ECDHSHA2NISTP256)
            default:
                continue
            }
        }
        return algorithms
    }

    mutating func readKeyAuthenticationAlgorithms() -> KeyAuthenticationAlgorithms? {
        guard var string = self.readSSHString() else {
            return nil
        }
        guard let list = string.readString(length: string.readableBytes) else {
            return []
        }
        var algorithms: KeyAuthenticationAlgorithms = []
        for element in list.split(separator: ",") {
            switch element {
            case "ssh-ed25519":
                algorithms.insert(.SSHED25519)
            case "ecdsa-sha2-nistp521":
                algorithms.insert(.ECDSASHA2NISTP521)
            case "ecdsa-sha2-nistp384":
                algorithms.insert(.ECDSASHA2NISTP384)
            case "ecdsa-sha2-nistp256":
                algorithms.insert(.ECDSASHA2NISTP256)
            default:
                continue
            }
        }
        return algorithms
    }

    mutating func readEncryptionAlgorithms() -> EncryptionAlgorithms? {
        guard var string = self.readSSHString() else {
            return nil
        }
        guard let list = string.readString(length: string.readableBytes) else {
            return []
        }
        var algorithms: EncryptionAlgorithms = []
        for element in list.split(separator: ",") {
            switch element {
            case "aes256-gcm@openssh.com":
                algorithms.insert(.AES256GCM)
            default:
                continue
            }
        }
        return algorithms
    }

    mutating func readMACAlgorithms() -> MACAlgorithms? {
        guard var string = self.readSSHString() else {
            return nil
        }
        guard let list = string.readString(length: string.readableBytes) else {
            return []
        }
        var algorithms: MACAlgorithms = []
        for element in list.split(separator: ",") {
            switch element {
            case "hmac-sha2-256":
                algorithms.insert(.HMACSHA2256)
            default:
                continue
            }
        }
        return algorithms
    }

    mutating func readCompressionAlgorithms() -> CompressionAlgorithms? {
        guard var string = self.readSSHString() else {
            return nil
        }
        guard let list = string.readString(length: string.readableBytes) else {
            return []
        }
        let algorithms: CompressionAlgorithms = []
        for element in list.split(separator: ",") {
            switch element {
            default:
                continue
            }
        }
        return algorithms
    }

    mutating func readLanguages() -> Languages? {
        guard var string = self.readSSHString() else {
            return nil
        }
        guard let list = string.readString(length: string.readableBytes) else {
            return []
        }
        let algorithms: Languages = []
        for element in list.split(separator: ",") {
            switch element {
            default:
                continue
            }
        }
        return algorithms
    }
}
