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

import Foundation
import NIO
import NIOFoundationCompat
import CryptoKit


/// A representation of an SSH signature.
///
/// NIOSSH supports only ECC-based signatures, either with ECDSA or Ed25519.
internal struct SSHSignature {
    internal var backingSignature: BackingSignature

    internal init(backingSignature: BackingSignature) {
        self.backingSignature = backingSignature
    }
}


extension SSHSignature {
    /// The various signature types that can be used with NIOSSH.
    internal enum BackingSignature {
        case ed25519(RawBytes)  // There is no structured Signature type for Curve25519, and we may want Data or ByteBuffer.
        case ecdsaP256(P256.Signing.ECDSASignature)

        internal enum RawBytes {
            case byteBuffer(ByteBuffer)
            case data(Data)
        }
    }

    /// The prefix of an Ed25519 signature.
    fileprivate static let ed25519SignaturePrefix = "ssh-ed25519".utf8

    /// The prefix of a P256 ECDSA public key.
    fileprivate static let ecdsaP256SignaturePrefix = "ecdsa-sha2-nistp256".utf8
}


extension ByteBuffer {
    /// Writes an SSH host key to this `ByteBuffer`.
    @discardableResult
    mutating func writeSSHSignature(_ sig: SSHSignature) -> Int {
        switch sig.backingSignature {
        case .ed25519(let sig):
            return self.writeEd25519Signature(signatureBytes: sig)
        case .ecdsaP256(let sig):
            return self.writeECDSAP256Signature(baseSignature: sig)
        }
    }

    private mutating func writeEd25519Signature(signatureBytes: SSHSignature.BackingSignature.RawBytes) -> Int {
        // The Ed25519 signature format is easy: the ed25519 signature prefix, followed by
        // the raw signature bytes.
        var writtenLength = self.writeSSHString(SSHSignature.ed25519SignaturePrefix)

        switch signatureBytes {
        case .byteBuffer(var buf):
            writtenLength += self.writeSSHString(&buf)
        case .data(let d):
            writtenLength += self.writeSSHString(d)
        }

        return writtenLength
    }

    private mutating func writeECDSAP256Signature(baseSignature: P256.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(SSHSignature.ecdsaP256SignaturePrefix)

        // For ECDSA-P256, the key format is `mpint r` followed by `mpint s`. In this context, `r` is the
        // first 32 bytes, and `s` is the second.
        let rawRepresentation = baseSignature.rawRepresentation
        precondition(rawRepresentation.count == 64, "Unexpected size for P256 key")
        let rBytes: Data = rawRepresentation.prefix(32)
        let sBytes: Data = rawRepresentation.dropFirst(32)

        writtenLength += self.writePositiveMPInt(rBytes)
        writtenLength += self.writePositiveMPInt(sBytes)

        return writtenLength
    }

    mutating func readSSHSignature() throws -> SSHSignature? {
        return try self.rewindOnNilOrError { buffer in
            // The wire format always begins with an SSH string containing the signature format identifier. Let's grab that.
            guard let signatureIdentifierBytes = buffer.readSSHString() else {
                return nil
            }

            // Now we need to check if they match our supported signature algorithms.
            let bytesView = signatureIdentifierBytes.readableBytesView
            if bytesView.elementsEqual(SSHSignature.ed25519SignaturePrefix) {
                return try buffer.readEd25519Signature()
            } else if bytesView.elementsEqual(SSHSignature.ecdsaP256SignaturePrefix) {
                return try buffer.readECDSAP256Signature()
            } else {
                // We don't know this signature type.
                throw NIOSSHError.unknownSignature
            }
        }
    }

    /// A helper function that reads an Ed25519 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readEd25519Signature() throws -> SSHSignature? {
        // For ed25519 the signature is just r||s encoded as a String.
        guard let sigBytes = self.readSSHString() else {
            return nil
        }

        return SSHSignature(backingSignature: .ed25519(.byteBuffer(sigBytes)))
    }

    /// A helper function that reads an ECDSA P-256 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP256Signature() throws -> SSHSignature? {
        // For ECDSA-P256, the key format is `mpint r` followed by `mpint s`.
        // We don't need them as mpints, so let's treat them as strings instead.
        guard let rBytes = self.readSSHString(),
              let sBytes = self.readSSHString() else {
            return nil
        }

        // Time to put these into the raw format that CryptoKit wants. This is r || s, with each
        // integer explicitly left-padded with zeros.
        let signature = try ECDSASignatureHelper(r: rBytes, s: sBytes).toECDSASignature()
        return SSHSignature(backingSignature: .ecdsaP256(signature))
    }
}


/// A structure that helps store ECDSA signatures on the stack temporarily to avoid unnecessary memory allocation.
///
/// CryptoKit would like to receive ECDSA signatures in the form of `r || s`, where `r` and `s` are both left-padded
/// with zeros. We know that for P256 the ECDSA signature size is going to be 64 bytes, as each of the P256 points are
/// 32 bytes wide. To avoid an unnecessary memory allocation, we use this data structure to provide some heap space to
/// store this in.
fileprivate struct ECDSASignatureHelper {
    private var storage: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64) = (0, 0, 0, 0, 0, 0, 0, 0)

    fileprivate init(r: ByteBuffer, s: ByteBuffer) {
        precondition(MemoryLayout<ECDSASignatureHelper>.size == 64, "Invalid width for ECDSA signature helper.")

        let rByteView = r.mpIntView
        let sByteView = s.mpIntView

        let rByteStartingOffset = 32 - rByteView.count
        let sByteStartingOffset = 32 - sByteView.count

        withUnsafeMutableBytes(of: &self.storage) { storagePtr in
            let rPtr = UnsafeMutableRawBufferPointer(rebasing: storagePtr[rByteStartingOffset..<32])
            let sPtr = UnsafeMutableRawBufferPointer(rebasing: storagePtr[(sByteStartingOffset + 32)...])

            precondition(rPtr.count == rByteView.count)
            precondition(sPtr.count == sByteView.count)

            rPtr.copyBytes(from: rByteView)
            sPtr.copyBytes(from: sByteView)
        }
    }

    func toECDSASignature() throws -> P256.Signing.ECDSASignature {
        return try withUnsafeBytes(of: self.storage) { storagePtr in
            return try P256.Signing.ECDSASignature(rawRepresentation: storagePtr)
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
