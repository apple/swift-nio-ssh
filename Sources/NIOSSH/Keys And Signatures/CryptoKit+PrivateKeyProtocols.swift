//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore
import Crypto

struct Curve25519Signature: NIOSSHSignatureProtocol {
    static let signaturePrefix = "ssh-ed25519"

    let rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeEd25519Signature(signature: self)
    }

    static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard var rawRepresentation = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHSignature
        }

        return Self(rawRepresentation: rawRepresentation.readData(length: rawRepresentation.readableBytes)!)
    }
}

extension Curve25519.Signing.PrivateKey: NIOSSHPrivateKeyProtocol {
    public static var keyPrefix: String { "ssh-ed25519" }
    
    public var sshPublicKey: NIOSSHPublicKeyProtocol { publicKey }

    public func sshSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignature {
        let signature = try Curve25519Signature(rawRepresentation: self.signature(for: data))
        return NIOSSHSignature(backingSignature: .ed25519(signature))
    }
}

extension P256.Signing.ECDSASignature: NIOSSHSignatureProtocol {
    public static var signaturePrefix: String { "ecdsa-sha2-nistp256" }

    public func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeECDSAP256Signature(baseSignature: self)
    }

    public static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard let rawRepresentation = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHSignature
        }

        return try Self(rawRepresentation: rawRepresentation.readableBytesView)
    }
}

extension P256.Signing.PrivateKey: NIOSSHPrivateKeyProtocol {
    public static var keyPrefix: String { "ecdsa-sha2-nistp256" }
    
    public var sshPublicKey: NIOSSHPublicKeyProtocol { publicKey }

    public func sshSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignature {
        return try NIOSSHSignature(backingSignature: .p256(self.signature(for: data)))
    }
}

extension P384.Signing.ECDSASignature: NIOSSHSignatureProtocol {
    public static var signaturePrefix: String { "ecdsa-sha2-nistp384" }

    public func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeECDSAP384Signature(baseSignature: self)
    }

    public static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard let rawRepresentation = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHSignature
        }

        return try Self(rawRepresentation: rawRepresentation.readableBytesView)
    }
}

extension P384.Signing.PrivateKey: NIOSSHPrivateKeyProtocol {
    public static var keyPrefix: String { "ecdsa-sha2-nistp384" }
    
    public var sshPublicKey: NIOSSHPublicKeyProtocol { publicKey }

    public func sshSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignature {
        return try NIOSSHSignature(backingSignature: .p384(self.signature(for: data)))
    }
}

extension P521.Signing.ECDSASignature: NIOSSHSignatureProtocol {
    public static var signaturePrefix: String { "ecdsa-sha2-nistp521" }

    public func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeECDSAP521Signature(baseSignature: self)
    }

    public static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard let rawRepresentation = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHSignature
        }

        return try Self(rawRepresentation: rawRepresentation.readableBytesView)
    }
}

extension P521.Signing.PrivateKey: NIOSSHPrivateKeyProtocol {
    public static var keyPrefix: String {
        "ecdsa-sha2-nistp521"
    }
    
    public var sshPublicKey: NIOSSHPublicKeyProtocol { publicKey }

    public func sshSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignature {
        return try NIOSSHSignature(backingSignature: .p521(self.signature(for: data)))
    }
}

#if canImport(Darwin)
extension SecureEnclave.P256.Signing.PrivateKey: NIOSSHPrivateKeyProtocol {
    public static var keyPrefix: String { P256.Signing.PrivateKey.keyPrefix }
    
    public var sshPublicKey: NIOSSHPublicKeyProtocol { publicKey }

    public func sshSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignature {
        return try NIOSSHSignature(backingSignature: .p256(self.signature(for: data)))
    }
}
#endif