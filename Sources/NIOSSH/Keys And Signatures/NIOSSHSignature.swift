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
import NIOFoundationCompat

/// A representation of an SSH signature.
///
/// This type is intentionally highly opaque: we don't expect users to do anything with this directly.
/// Instead, we expect them to work with other APIs available on our opaque types.
public struct NIOSSHSignature: Hashable, Sendable {
    internal enum BackingSignature {
        case ed25519(Curve25519Signature)
        case p521(P521.Signing.ECDSASignature)
        case p384(P384.Signing.ECDSASignature)
        case p256(P256.Signing.ECDSASignature)
        case other(NIOSSHSignatureProtocol)

        var signaturePrefix: String {
            switch self {
            case .ed25519: return Curve25519Signature.signaturePrefix
            case .p521: return P521.Signing.ECDSASignature.signaturePrefix
            case .p384: return P384.Signing.ECDSASignature.signaturePrefix
            case .p256: return P256.Signing.ECDSASignature.signaturePrefix
            case .other(let sig): return sig.signaturePrefix
            }
        }

        var rawRepresentation: Data {
            switch self {
            case .ed25519(let sig): return sig.rawRepresentation
            case .p521(let sig): return sig.rawRepresentation
            case .p384(let sig): return sig.rawRepresentation
            case .p256(let sig): return sig.rawRepresentation
            case .other(let sig): return sig.rawRepresentation
            }
        }

        func write(to buffer: inout ByteBuffer) -> Int {
            switch self {
            case .ed25519(let sig): return buffer.writeEd25519Signature(signature: sig)
            case .p521(let sig): return buffer.writeECDSAP521Signature(baseSignature: sig)
            case .p384(let sig): return buffer.writeECDSAP384Signature(baseSignature: sig)
            case .p256(let sig): return buffer.writeECDSAP256Signature(baseSignature: sig)
            case .other(let sig): return sig.write(to: &buffer)
            }
        }
    }

    internal var _backingSignature: BackingSignature
    public var backingSignature: NIOSSHSignatureProtocol {
        switch self._backingSignature {
        case .ed25519(let sig): return sig
        case .p521(let sig): return sig
        case .p384(let sig): return sig
        case .p256(let sig): return sig
        case .other(let sig):
            return sig
        }
    }

    internal init(backingSignature: BackingSignature) {
        self._backingSignature = backingSignature
    }

    public init(_ signature: NIOSSHSignatureProtocol) {
        // In case that end-users obtain one of the built-in signatures.
        switch signature {
        case let signature as Curve25519Signature:
            _backingSignature = .ed25519(signature)
        case let signature as P521.Signing.ECDSASignature:
            _backingSignature = .p521(signature)
        case let signature as P384.Signing.ECDSASignature:
            _backingSignature = .p384(signature)
        case let signature as P256.Signing.ECDSASignature:
            _backingSignature = .p256(signature)
        default:
            _backingSignature = .other(signature)
        }
    }

    public static func ==(lhs: NIOSSHSignature, rhs: NIOSSHSignature) -> Bool {
        lhs._backingSignature.signaturePrefix == rhs._backingSignature.signaturePrefix &&
            lhs._backingSignature.rawRepresentation == rhs._backingSignature.rawRepresentation
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(_backingSignature.signaturePrefix)
        hasher.combine(_backingSignature.rawRepresentation)
    }
}

extension ByteBuffer {
    /// Writes an SSH host key to this `ByteBuffer`.
    @discardableResult
    mutating func writeSSHSignature(_ sig: NIOSSHSignature) -> Int {
        sig._backingSignature.write(to: &self)
    }

    mutating func writeEd25519Signature(signature: Curve25519Signature) -> Int {
        // The Ed25519 signature format is easy: the ed25519 signature prefix, followed by
        // the raw signature bytes.
        var writtenLength = self.writeSSHString(Curve25519Signature.signaturePrefix.utf8)
        writtenLength += self.writeSSHString(signature.rawRepresentation)

        return writtenLength
    }

    mutating func writeECDSAP256Signature(baseSignature: P256.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(P256.Signing.ECDSASignature.signaturePrefix.utf8)

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

    mutating func writeECDSAP384Signature(baseSignature: P384.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(P384.Signing.ECDSASignature.signaturePrefix.utf8)

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

    mutating func writeECDSAP521Signature(baseSignature: P521.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(P521.Signing.ECDSASignature.signaturePrefix.utf8)

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
        try self.rewindOnNilOrError { buffer -> NIOSSHSignature? in
            // The wire format always begins with an SSH string containing the signature format identifier. Let's grab that.
            guard var signatureIdentifierBytes = buffer.readSSHString() else {
                return nil
            }

            // Now we need to check if they match our supported signature algorithms.
            let bytesView = signatureIdentifierBytes.readableBytesView
            if bytesView.elementsEqual(Curve25519Signature.signaturePrefix.utf8) {
                return try buffer.readEd25519Signature()
            } else if bytesView.elementsEqual(P256.Signing.ECDSASignature.signaturePrefix.utf8) {
                return try buffer.readECDSAP256Signature()
            } else if bytesView.elementsEqual(P384.Signing.ECDSASignature.signaturePrefix.utf8) {
                return try buffer.readECDSAP384Signature()
            } else if bytesView.elementsEqual(P521.Signing.ECDSASignature.signaturePrefix.utf8) {
                return try buffer.readECDSAP521Signature()
            } else {
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
        guard var sigBytes = self.readSSHString() else {
            return nil
        }

        return NIOSSHSignature(backingSignature: .ed25519(Curve25519Signature(
            rawRepresentation: sigBytes.readData(length: sigBytes.readableBytes)!
        )))
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
        return try NIOSSHSignature(
            backingSignature: .p256(ECDSASignatureHelper.toECDSASignature(r: rBytes, s: sBytes))
        )
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
        return try NIOSSHSignature(backingSignature: .p384(ECDSASignatureHelper.toECDSASignature(r: rBytes, s: sBytes)))
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
        return try NIOSSHSignature(backingSignature: .p521(ECDSASignatureHelper.toECDSASignature(r: rBytes, s: sBytes)))
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
