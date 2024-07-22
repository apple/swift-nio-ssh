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

extension Curve25519.Signing.PublicKey: NIOSSHPublicKeyProtocol {
    internal static var prefix: String { "ssh-ed25519" }
    public static var publicKeyPrefix: String? { Self.prefix }
    public var publicKeyPrefix: String { Self.prefix }

    public func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignature, for data: D) -> Bool {
        guard case .ed25519(let signature) = signature._backingSignature else {
            return false
        }

        return self.isValidSignature(signature.rawRepresentation, for: data)
    }

    public func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeEd25519PublicKey(baseKey: self)
    }

    public func writeHostKey(to buffer: inout ByteBuffer) -> Int {
        var writtenBytes = 0
        writtenBytes += buffer.writeSSHString(self.publicKeyPrefix.utf8)
        writtenBytes += self.write(to: &buffer)
        return writtenBytes
    }

    public static func read(from buffer: inout ByteBuffer) throws -> Self? {
        guard let qBytes = buffer.readSSHString() else {
            return nil
        }

        return try Curve25519.Signing.PublicKey(rawRepresentation: qBytes.readableBytesView)
    }
}

extension P256.Signing.PublicKey: NIOSSHPublicKeyProtocol {
    internal static var prefix: String { "ecdsa-sha2-nistp256" }
    public static var publicKeyPrefix: String? { Self.prefix }
    public var publicKeyPrefix: String { Self.prefix }

    public func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignature, for data: D) -> Bool {
        guard case .p256(let signature) = signature._backingSignature else {
            return false
        }

        return self.isValidSignature(signature, for: data)
    }

    public func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeECDSAP256PublicKey(baseKey: self)
    }

    public func writeHostKey(to buffer: inout ByteBuffer) -> Int {
        var writtenBytes = 0
        writtenBytes += buffer.writeSSHString(self.publicKeyPrefix.utf8)
        writtenBytes += self.write(to: &buffer)
        return writtenBytes
    }

    public static func read(from buffer: inout ByteBuffer) throws -> Self? {
        // For ECDSA-P256, the key format is the string "nistp256" followed by the
        // the public point Q.
        guard var domainParameter = buffer.readSSHString() else {
            return nil
        }
        guard domainParameter.readableBytesView.elementsEqual("nistp256".utf8) else {
            let unexpectedParameter = domainParameter.readString(length: domainParameter.readableBytes) ?? "<unknown domain parameter>"
            throw NIOSSHError.invalidDomainParametersForKey(parameters: unexpectedParameter)
        }

        guard let qBytes = buffer.readSSHString() else {
            return nil
        }

        return try P256.Signing.PublicKey(x963Representation: qBytes.readableBytesView)
    }
}

extension P384.Signing.PublicKey: NIOSSHPublicKeyProtocol {
    internal static var prefix: String { "ecdsa-sha2-nistp384" }
    public static var publicKeyPrefix: String? { Self.prefix }
    public var publicKeyPrefix: String { Self.prefix }

    public func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignature, for data: D) -> Bool {
        guard case .p384(let signature) = signature._backingSignature else {
            return false
        }
        
        return self.isValidSignature(signature, for: data)
    }

    public func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeECDSAP384PublicKey(baseKey: self)
    }

    public func writeHostKey(to buffer: inout ByteBuffer) -> Int {
        var writtenBytes = 0
        writtenBytes += buffer.writeSSHString(self.publicKeyPrefix.utf8)
        writtenBytes += self.write(to: &buffer)
        return writtenBytes
    }

    public static func read(from buffer: inout ByteBuffer) throws -> Self? {
        // For ECDSA-P384, the key format is the string "nistp384" followed by the
        // the public point Q.
        guard var domainParameter = buffer.readSSHString() else {
            return nil
        }
        guard domainParameter.readableBytesView.elementsEqual("nistp384".utf8) else {
            let unexpectedParameter = domainParameter.readString(length: domainParameter.readableBytes) ?? "<unknown domain parameter>"
            throw NIOSSHError.invalidDomainParametersForKey(parameters: unexpectedParameter)
        }

        guard let qBytes = buffer.readSSHString() else {
            return nil
        }

        return try P384.Signing.PublicKey(x963Representation: qBytes.readableBytesView)
    }
}

extension P521.Signing.PublicKey: NIOSSHPublicKeyProtocol {
    internal static var prefix: String { "ecdsa-sha2-nistp521" }
    public static var publicKeyPrefix: String? { Self.prefix }
    public var publicKeyPrefix: String { Self.prefix }

    public func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignature, for data: D) -> Bool {
        guard case .p521(let signature) = signature._backingSignature else {
            return false
        }
        
        return self.isValidSignature(signature, for: data)
    }

    public func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeECDSAP521PublicKey(baseKey: self)
    }

    public func writeHostKey(to buffer: inout ByteBuffer) -> Int {
        var writtenBytes = 0
        writtenBytes += buffer.writeSSHString(self.publicKeyPrefix.utf8)
        writtenBytes += self.write(to: &buffer)
        return writtenBytes
    }

    public static func read(from buffer: inout ByteBuffer) throws -> Self? {
        // For ECDSA-P521, the key format is the string "nistp521" followed by the
        // the public point Q.
        guard var domainParameter = buffer.readSSHString() else {
            return nil
        }
        guard domainParameter.readableBytesView.elementsEqual("nistp521".utf8) else {
            let unexpectedParameter = domainParameter.readString(length: domainParameter.readableBytes) ?? "<unknown domain parameter>"
            throw NIOSSHError.invalidDomainParametersForKey(parameters: unexpectedParameter)
        }

        guard let qBytes = buffer.readSSHString() else {
            return nil
        }

        return try P521.Signing.PublicKey(x963Representation: qBytes.readableBytesView)
    }
}