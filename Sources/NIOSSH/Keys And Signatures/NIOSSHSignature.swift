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

import Crypto
import Foundation
import NIOCore
import NIOFoundationCompat

/// A representation of an SSH signature.
///
/// This type is intentionally highly opaque: we don't expect users to do anything with this directly.
/// Instead, we expect them to work with other APIs available on our opaque types.
public struct NIOSSHSignature: Hashable {
    internal var backingSignature: BackingSignature

    internal init(backingSignature: BackingSignature) {
        self.backingSignature = backingSignature
    }
}

extension NIOSSHSignature {
    /// The various signature types that can be used with NIOSSH.
    internal enum BackingSignature {
        case ed25519(RawBytes) // There is no structured Signature type for Curve25519, and we may want Data or ByteBuffer.
        case ecdsaP256(P256.Signing.ECDSASignature)
        case ecdsaP384(P384.Signing.ECDSASignature)
        case ecdsaP521(P521.Signing.ECDSASignature)
        case custom(NIOSSHSignatureProtocol)

        internal enum RawBytes {
            case byteBuffer(ByteBuffer)
            case data(Data)
        }
    }

    /// The prefix of an Ed25519 signature.
    fileprivate static let ed25519SignaturePrefix = "ssh-ed25519".utf8

    /// The prefix of a P256 ECDSA public key.
    fileprivate static let ecdsaP256SignaturePrefix = "ecdsa-sha2-nistp256".utf8

    /// The prefix of a P384 ECDSA public key.
    fileprivate static let ecdsaP384SignaturePrefix = "ecdsa-sha2-nistp384".utf8

    /// The prefix of a P521 ECDSA public key.
    fileprivate static let ecdsaP521SignaturePrefix = "ecdsa-sha2-nistp521".utf8
}

extension NIOSSHSignature.BackingSignature.RawBytes: Equatable {
    public static func == (lhs: NIOSSHSignature.BackingSignature.RawBytes, rhs: NIOSSHSignature.BackingSignature.RawBytes) -> Bool {
        switch (lhs, rhs) {
        case (.byteBuffer(let lhs), .byteBuffer(let rhs)):
            return lhs == rhs
        case (.data(let lhs), .data(let rhs)):
            return lhs == rhs
        case (.byteBuffer(let lhs), .data(let rhs)):
            return lhs.readableBytesView.elementsEqual(rhs)
        case (.data(let lhs), .byteBuffer(let rhs)):
            return rhs.readableBytesView.elementsEqual(lhs)
        }
    }
}

extension NIOSSHSignature.BackingSignature.RawBytes: Hashable {}

extension NIOSSHSignature.BackingSignature: Equatable {
    static func == (lhs: NIOSSHSignature.BackingSignature, rhs: NIOSSHSignature.BackingSignature) -> Bool {
        // We implement equatable in terms of the key representation.
        switch (lhs, rhs) {
        case (.ed25519(let lhs), .ed25519(let rhs)):
            return lhs == rhs
        case (.ecdsaP256(let lhs), .ecdsaP256(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP384(let lhs), .ecdsaP384(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP521(let lhs), .ecdsaP521(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.custom(let lhs), .custom(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ed25519, _),
             (.ecdsaP256, _),
             (.ecdsaP384, _),
             (.ecdsaP521, _),
             (.custom, _):
            return false
        }
    }
}

extension NIOSSHSignature.BackingSignature: Hashable {
    func hash(into hasher: inout Hasher) {
        switch self {
        case .ed25519(let bytes):
            hasher.combine(0)
            hasher.combine(bytes)
        case .ecdsaP256(let sig):
            hasher.combine(1)
            hasher.combine(sig.rawRepresentation)
        case .ecdsaP384(let sig):
            hasher.combine(2)
            hasher.combine(sig.rawRepresentation)
        case .ecdsaP521(let sig):
            hasher.combine(3)
            hasher.combine(sig.rawRepresentation)
        case .custom(let sig):
            hasher.combine(4)
            hasher.combine(sig.signaturePrefix)
            hasher.combine(sig.rawRepresentation)
        }
    }
}

extension ByteBuffer {
    /// Writes an SSH host key to this `ByteBuffer`.
    @discardableResult
    mutating func writeSSHSignature(_ sig: NIOSSHSignature) -> Int {
        switch sig.backingSignature {
        case .ed25519(let sig):
            return self.writeEd25519Signature(signatureBytes: sig)
        case .ecdsaP256(let sig):
            return self.writeECDSAP256Signature(baseSignature: sig)
        case .ecdsaP384(let sig):
            return self.writeECDSAP384Signature(baseSignature: sig)
        case .ecdsaP521(let sig):
            return self.writeECDSAP521Signature(baseSignature: sig)
        case .custom(let sig):
            var writtenBytes = writeSSHString(sig.signaturePrefix.utf8)
            writtenBytes += sig.write(to: &self)
            return writtenBytes
        }
    }

    private mutating func writeEd25519Signature(signatureBytes: NIOSSHSignature.BackingSignature.RawBytes) -> Int {
        // The Ed25519 signature format is easy: the ed25519 signature prefix, followed by
        // the raw signature bytes.
        var writtenLength = self.writeSSHString(NIOSSHSignature.ed25519SignaturePrefix)

        switch signatureBytes {
        case .byteBuffer(var buf):
            writtenLength += self.writeSSHString(&buf)
        case .data(let d):
            writtenLength += self.writeSSHString(d)
        }

        return writtenLength
    }

    private mutating func writeECDSAP256Signature(baseSignature: P256.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(NIOSSHSignature.ecdsaP256SignaturePrefix)

        // For ECDSA-P256, the key format is `mpint r` followed by `mpint s`. In this context, `r` is the
        // first 32 bytes, and `s` is the second.
        let rawRepresentation = baseSignature.rawRepresentation
        precondition(rawRepresentation.count == 64, "Unexpected size for P256 key")
        let rBytes: Data = rawRepresentation.prefix(32)
        let sBytes: Data = rawRepresentation.dropFirst(32)

        writtenLength += self.writeCompositeSSHString { buffer in
            var written = 0
            written += buffer.writePositiveMPInt(rBytes)
            written += buffer.writePositiveMPInt(sBytes)
            return written
        }

        return writtenLength
    }

    private mutating func writeECDSAP384Signature(baseSignature: P384.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(NIOSSHSignature.ecdsaP384SignaturePrefix)

        // For ECDSA-P384, the key format is `mpint r` followed by `mpint s`. In this context, `r` is the
        // first 48 bytes, and `s` is the second.
        let rawRepresentation = baseSignature.rawRepresentation
        precondition(rawRepresentation.count == 96, "Unexpected size for P384 key")
        let rBytes: Data = rawRepresentation.prefix(48)
        let sBytes: Data = rawRepresentation.dropFirst(48)

        writtenLength += self.writeCompositeSSHString { buffer in
            var written = 0
            written += buffer.writePositiveMPInt(rBytes)
            written += buffer.writePositiveMPInt(sBytes)
            return written
        }

        return writtenLength
    }

    private mutating func writeECDSAP521Signature(baseSignature: P521.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(NIOSSHSignature.ecdsaP521SignaturePrefix)

        // For ECDSA-P521, the key format is `mpint r` followed by `mpint s`. In this context, `r` is the
        // first 66 bytes, and `s` is the second.
        let rawRepresentation = baseSignature.rawRepresentation
        precondition(rawRepresentation.count == 132, "Unexpected size for P521 key")
        let rBytes: Data = rawRepresentation.prefix(66)
        let sBytes: Data = rawRepresentation.dropFirst(66)

        writtenLength += self.writeCompositeSSHString { buffer in
            var written = 0
            written += buffer.writePositiveMPInt(rBytes)
            written += buffer.writePositiveMPInt(sBytes)
            return written
        }

        return writtenLength
    }

    mutating func readSSHSignature() throws -> NIOSSHSignature? {
        try self.rewindOnNilOrError { buffer in
            // The wire format always begins with an SSH string containing the signature format identifier. Let's grab that.
            guard var signatureIdentifierBytes = buffer.readSSHString() else {
                return nil
            }

            // Now we need to check if they match our supported signature algorithms.
            let bytesView = signatureIdentifierBytes.readableBytesView
            if bytesView.elementsEqual(NIOSSHSignature.ed25519SignaturePrefix) {
                return try buffer.readEd25519Signature()
            } else if bytesView.elementsEqual(NIOSSHSignature.ecdsaP256SignaturePrefix) {
                return try buffer.readECDSAP256Signature()
            } else if bytesView.elementsEqual(NIOSSHSignature.ecdsaP384SignaturePrefix) {
                return try buffer.readECDSAP384Signature()
            } else if bytesView.elementsEqual(NIOSSHSignature.ecdsaP521SignaturePrefix) {
                return try buffer.readECDSAP521Signature()
            } else {
                for signature in NIOSSHPublicKey.customSignatures {
                    if bytesView.elementsEqual(signature.signaturePrefix.utf8) {
                        let signature = try signature.read(from: &buffer)
                        return NIOSSHSignature(backingSignature: .custom(signature))
                    }
                }
                
                // We don't know this signature type.
                let signature = signatureIdentifierBytes.readString(length: signatureIdentifierBytes.readableBytes) ?? "<unknown signature>"
                throw NIOSSHError.unknownSignature(algorithm: signature)
            }
        }
    }

    /// A helper function that reads an Ed25519 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readEd25519Signature() throws -> NIOSSHSignature? {
        // For ed25519 the signature is just r||s encoded as a String.
        guard let sigBytes = self.readSSHString() else {
            return nil
        }

        return NIOSSHSignature(backingSignature: .ed25519(.byteBuffer(sigBytes)))
    }

    /// A helper function that reads an ECDSA P-256 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP256Signature() throws -> NIOSSHSignature? {
        // For ECDSA-P256, the key format is `mpint r` followed by `mpint s`.
        // We don't need them as mpints, so let's treat them as strings instead.
        guard var signatureBytes = self.readSSHString(),
            let rBytes = signatureBytes.readSSHString(),
            let sBytes = signatureBytes.readSSHString() else {
            return nil
        }

        // Time to put these into the raw format that CryptoKit wants. This is r || s, with each
        // integer explicitly left-padded with zeros.
        return try NIOSSHSignature(backingSignature: .ecdsaP256(ECDSASignatureHelper.toECDSASignature(r: rBytes, s: sBytes)))
    }

    /// A helper function that reads an ECDSA P-384 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP384Signature() throws -> NIOSSHSignature? {
        // For ECDSA-P384, the key format is `mpint r` followed by `mpint s`.
        // We don't need them as mpints, so let's treat them as strings instead.
        guard var signatureBytes = self.readSSHString(),
            let rBytes = signatureBytes.readSSHString(),
            let sBytes = signatureBytes.readSSHString() else {
            return nil
        }

        // Time to put these into the raw format that CryptoKit wants. This is r || s, with each
        // integer explicitly left-padded with zeros.
        return try NIOSSHSignature(backingSignature: .ecdsaP384(ECDSASignatureHelper.toECDSASignature(r: rBytes, s: sBytes)))
    }

    /// A helper function that reads an ECDSA P-521 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP521Signature() throws -> NIOSSHSignature? {
        // For ECDSA-P521, the key format is `mpint r` followed by `mpint s`.
        // We don't need them as mpints, so let's treat them as strings instead.
        guard var signatureBytes = self.readSSHString(),
            let rBytes = signatureBytes.readSSHString(),
            let sBytes = signatureBytes.readSSHString() else {
            return nil
        }

        // Time to put these into the raw format that CryptoKit wants. This is r || s, with each
        // integer explicitly left-padded with zeros.
        return try NIOSSHSignature(backingSignature: .ecdsaP521(ECDSASignatureHelper.toECDSASignature(r: rBytes, s: sBytes)))
    }
}

/// A structure that helps store ECDSA signatures on the stack temporarily to avoid unnecessary memory allocation.
///
/// CryptoKit would like to receive ECDSA signatures in the form of `r || s`, where `r` and `s` are both left-padded
/// with zeros. We know that for P256 the ECDSA signature size is going to be 64 bytes, as each of the P256 points are
/// 32 bytes wide. Similar logic applies up to P521, whose signatures are 132 bytes in size.
///
/// To avoid an unnecessary memory allocation, we use this data structure to provide some heap space to store these in.
/// This structure is wide enough for any of these signatures, and just uses the appropriate amount of space for whatever
/// algorithm is actually in use.
private struct ECDSASignatureHelper {
    private var storage: (
        UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
        UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
        UInt64
    ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    private init(r: ByteBuffer, s: ByteBuffer, pointSize: Int) {
        precondition(MemoryLayout<ECDSASignatureHelper>.size >= pointSize, "Invalid width for ECDSA signature helper.")

        let rByteView = r.mpIntView
        let sByteView = s.mpIntView

        let rByteStartingOffset = pointSize - rByteView.count
        let sByteStartingOffset = pointSize - sByteView.count

        withUnsafeMutableBytes(of: &self.storage) { storagePtr in
            let rPtr = UnsafeMutableRawBufferPointer(rebasing: storagePtr[rByteStartingOffset ..< pointSize])
            let sPtr = UnsafeMutableRawBufferPointer(rebasing: storagePtr[(sByteStartingOffset + pointSize) ..< (pointSize * 2)])

            precondition(rPtr.count == rByteView.count)
            precondition(sPtr.count == sByteView.count)

            rPtr.copyBytes(from: rByteView)
            sPtr.copyBytes(from: sByteView)
        }
    }

    static func toECDSASignature<Signature: ECDSASignatureProtocol>(r: ByteBuffer, s: ByteBuffer) throws -> Signature {
        let helper = ECDSASignatureHelper(r: r, s: s, pointSize: Signature.pointSize)
        return try withUnsafeBytes(of: helper.storage) { storagePtr in
            try Signature(rawRepresentation: UnsafeRawBufferPointer(rebasing: storagePtr.prefix(Signature.pointSize * 2)))
        }
    }
}

extension ByteBuffer {
    // A view onto the mpInt bytes. Strips off a leading 0 if it is present for
    // size reasons.
    fileprivate var mpIntView: ByteBufferView {
        var baseView = self.readableBytesView
        if baseView.first == 0 {
            baseView = baseView.dropFirst()
        }
        return baseView
    }
}

protocol ECDSASignatureProtocol {
    init<D>(rawRepresentation: D) throws where D: DataProtocol

    static var pointSize: Int { get }
}

extension P256.Signing.ECDSASignature: ECDSASignatureProtocol {
    static var pointSize: Int { 32 }
}

extension P384.Signing.ECDSASignature: ECDSASignatureProtocol {
    static var pointSize: Int { 48 }
}

extension P521.Signing.ECDSASignature: ECDSASignatureProtocol {
    static var pointSize: Int { 66 }
}
