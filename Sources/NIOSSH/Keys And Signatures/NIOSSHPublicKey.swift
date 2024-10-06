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

@preconcurrency import Crypto
import Foundation
import NIOCore

/// An SSH public key.
///
/// This object identifies a single SSH server or user. It is used as part of the SSH handshake and key exchange process,
/// is presented to clients that want to validate that they are communicating with the appropriate server, and is also used
/// to validate users.
///
/// This key is not capable of signing, only verifying.
public struct NIOSSHPublicKey: Sendable, Hashable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: NIOSSHPublicKeyProtocol

    internal init(backingKey: NIOSSHPublicKeyProtocol) {
        self.backingKey = backingKey
    }

    /// Create a ``NIOSSHPublicKey`` from the OpenSSH public key string.
    public init(openSSHPublicKey: String) throws {
        // The OpenSSH public key format is like this: "algorithm-id base64-encoded-key comments"
        //
        // We split on spaces, no more than twice. We then check if we know about the algorithm identifier and, if we
        // do, we parse the key.
        var components = ArraySlice(openSSHPublicKey.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true))
        guard let keyIdentifier = components.popFirst(), let keyData = components.popFirst() else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "invalid number of sections")
        }
        guard let rawBytes = Data(base64Encoded: String(keyData)) else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "could not base64-decode string")
        }

        var buffer = ByteBufferAllocator().buffer(capacity: rawBytes.count)
        buffer.writeContiguousBytes(rawBytes)
        guard let key = try buffer.readSSHHostKey() else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "incomplete key data")
        }
        guard key.keyPrefix.elementsEqual(keyIdentifier.utf8) else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "inconsistent key type within openssh key format")
        }
        self = key
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.backingKey.publicKeyPrefix)
        hasher.combine(self.backingKey.rawRepresentation)
    }

    public static func == (lhs: NIOSSHPublicKey, rhs: NIOSSHPublicKey) -> Bool {
        lhs.backingKey.publicKeyPrefix == rhs.backingKey.publicKeyPrefix &&
        lhs.backingKey.rawRepresentation == rhs.backingKey.rawRepresentation
    }
}

extension NIOSSHPublicKey {
    /// Verifies that a given `NIOSSHSignature` was created by the holder of the private key associated with this
    /// public key.
    internal func isValidSignature<DigestBytes: Digest>(_ signature: NIOSSHSignature, for digest: DigestBytes) -> Bool {
        digest.withUnsafeBytes { digestptr in
            self.backingKey.isValidSignature(signature, for: digestptr)
        }
    }

    internal func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignature, for data: D) -> Bool {
        self.backingKey.isValidSignature(signature, for: data)
    }

    internal func isValidSignature(_ signature: NIOSSHSignature, for bytes: ByteBuffer) -> Bool {
        return backingKey.isValidSignature(signature, for: bytes.readableBytesView)
    }

    internal func isValidSignature(_ signature: NIOSSHSignature, for payload: UserAuthSignablePayload) -> Bool {
        return backingKey.isValidSignature(signature, for: payload.bytes.readableBytesView)
    }
}

extension NIOSSHPublicKey {
    internal var keyPrefix: String.UTF8View {
        backingKey.publicKeyPrefix.utf8
    }

    internal static var knownAlgorithms: [String.UTF8View] {
        [
            Curve25519.Signing.PublicKey.prefix.utf8, 
            P256.Signing.PublicKey.prefix.utf8,
            P384.Signing.PublicKey.prefix.utf8,
            P521.Signing.PublicKey.prefix.utf8
        ]
    }
}

extension ByteBuffer {
    /// Writes an SSH host key to this `ByteBuffer`.
    @discardableResult
    mutating func writeSSHHostKey(_ key: NIOSSHPublicKey) -> Int {
        key.backingKey.writeHostKey(to: &self)
    }

    /// Writes an SSH host key to this `ByteBuffer`, without a prefix.
    ///
    /// This is mostly used as part of the certified key structure.
    @discardableResult
    mutating func writePublicKeyWithoutPrefix(_ key: NIOSSHPublicKey) -> Int {
        key.backingKey.write(to: &self)
    }

    mutating func readSSHHostKey() throws -> NIOSSHPublicKey? {
        try self.rewindOnNilOrError { buffer in
            // The wire format always begins with an SSH string containing the key format identifier. Let's grab that.
            guard let keyIdentifierBytes = buffer.readSSHString() else {
                return nil
            }

            // Now we need to check if they match our supported key algorithms.
            return try buffer.readPublicKeyWithoutPrefixForIdentifier(keyIdentifierBytes.readableBytesView)
        }
    }

    mutating func readPublicKeyWithoutPrefixForIdentifier<Bytes: Collection>(_ keyIdentifierBytes: Bytes) throws -> NIOSSHPublicKey? where Bytes.Element == UInt8 {
        try self.rewindOnNilOrError { buffer in
            if keyIdentifierBytes.elementsEqual(Curve25519.Signing.PublicKey.prefix.utf8) {
                return try Curve25519.Signing.PublicKey.read(from: &buffer)
                    .map(NIOSSHPublicKey.init)
            } else if keyIdentifierBytes.elementsEqual(P256.Signing.PublicKey.prefix.utf8) {
                return try P256.Signing.PublicKey.read(from: &buffer)
                    .map(NIOSSHPublicKey.init)
            } else if keyIdentifierBytes.elementsEqual(P384.Signing.PublicKey.prefix.utf8) {
                return try P384.Signing.PublicKey.read(from: &buffer)
                    .map(NIOSSHPublicKey.init)
            } else if keyIdentifierBytes.elementsEqual(P521.Signing.PublicKey.prefix.utf8) {
                return try P521.Signing.PublicKey.read(from: &buffer)
                    .map(NIOSSHPublicKey.init)
            } else {
                // We don't know this public key type. Maybe the certified keys do.
                return try buffer.readCertifiedKeyWithoutKeyPrefix(keyIdentifierBytes)
                    .map(NIOSSHPublicKey.init)
            }
        }
    }

    mutating func writeEd25519PublicKey(baseKey: Curve25519.Signing.PublicKey) -> Int {
        // For Ed25519 the key format is  Q as a String.
        self.writeSSHString(baseKey.rawRepresentation)
    }

    mutating func writeECDSAP256PublicKey(baseKey: P256.Signing.PublicKey) -> Int {
        // For ECDSA-P256, the key format is the string "nistp256", followed by the
        // the public point Q.
        var writtenBytes = 0
        writtenBytes += self.writeSSHString("nistp256".utf8)
        writtenBytes += self.writeSSHString(baseKey.x963Representation)
        return writtenBytes
    }

    mutating func writeECDSAP384PublicKey(baseKey: P384.Signing.PublicKey) -> Int {
        // For ECDSA-P384, the key format is the string "nistp384", followed by the
        // the public point Q.
        var writtenBytes = 0
        writtenBytes += self.writeSSHString("nistp384".utf8)
        writtenBytes += self.writeSSHString(baseKey.x963Representation)
        return writtenBytes
    }

    mutating func writeECDSAP521PublicKey(baseKey: P521.Signing.PublicKey) -> Int {
        // For ECDSA-P521, the key format is the string "nistp521", followed by the
        // the public point Q.
        var writtenBytes = 0
        writtenBytes += self.writeSSHString("nistp521".utf8)
        writtenBytes += self.writeSSHString(baseKey.x963Representation)
        return writtenBytes
    }

    /// A helper function for complex readers that will reset a buffer on nil or on error, as though the read
    /// never occurred.
    internal mutating func rewindOnNilOrError<T>(_ body: (inout ByteBuffer) throws -> T?) rethrows -> T? {
        let originalSelf = self

        let returnValue: T?
        do {
            returnValue = try body(&self)
        } catch {
            self = originalSelf
            throw error
        }

        if returnValue == nil {
            self = originalSelf
        }

        return returnValue
    }
}

extension String {
    /// Takes a NIOSSHPublicKey and turns it into OpenSSH public key string in the format of "algorithm-id base64-encoded-key"
    public init(openSSHPublicKey: NIOSSHPublicKey) {
        var buffer = ByteBuffer()
        buffer.writeSSHHostKey(openSSHPublicKey)
        let next = Data(buffer.readableBytesView).base64EncodedString()
        let publicKeyString = String(openSSHPublicKey.keyPrefix) + " " + next
        self = publicKeyString
    }
}
