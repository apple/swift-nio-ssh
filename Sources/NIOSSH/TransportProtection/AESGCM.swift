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
import NIO
import NIOFoundationCompat

/// A base class for the AES GCM transport protection implementations.
///
/// All four AES GCM transport protection implementations are almost identical: they differ only in their
/// expected key sizes and whether or not they negotiate an explicit MAC. As this is simply static data, we
/// can use a single base class to implement the logic and have the subclasses provide the static data we need.
internal class AESGCMTransportProtection {
    private var outboundEncryptionKey: SymmetricKey
    private var inboundEncryptionKey: SymmetricKey
    private var outboundNonce: SSHAESGCMNonce
    private var inboundNonce: SSHAESGCMNonce

    class var cipherName: String {
        fatalError("Must override cipher name")
    }

    class var macName: String? {
        fatalError("Must override MAC name")
    }

    class var keySizes: ExpectedKeySizes {
        fatalError("Must override key size")
    }

    required init(initialKeys: NIOSSHSessionKeys) throws {
        guard initialKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
            initialKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8 else {
            throw NIOSSHError.invalidKeySize
        }

        self.outboundEncryptionKey = initialKeys.outboundEncryptionKey
        self.inboundEncryptionKey = initialKeys.inboundEncryptionKey
        self.outboundNonce = try SSHAESGCMNonce(keyExchangeResult: initialKeys.initialOutboundIV)
        self.inboundNonce = try SSHAESGCMNonce(keyExchangeResult: initialKeys.initialInboundIV)
    }
}

extension AESGCMTransportProtection: NIOSSHTransportProtection {
    static var cipherBlockSize: Int {
        16
    }

    var macBytes: Int {
        16
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        guard newKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
            newKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8 else {
            throw NIOSSHError.invalidKeySize
        }

        self.outboundEncryptionKey = newKeys.outboundEncryptionKey
        self.inboundEncryptionKey = newKeys.inboundEncryptionKey
        self.outboundNonce = try SSHAESGCMNonce(keyExchangeResult: newKeys.initialOutboundIV)
        self.inboundNonce = try SSHAESGCMNonce(keyExchangeResult: newKeys.initialInboundIV)
    }

    func decryptFirstBlock(_: inout ByteBuffer) throws {
        // For us, decrypting the first block is very easy: do nothing. The length bytes are already
        // unencrypted!
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer) throws -> ByteBuffer {
        var plaintext: Data

        // Establish a nested scope here to avoid the byte buffer views causing an accidental CoW.
        do {
            // The first 4 bytes are the length. The last 16 are the tag. Everything else is ciphertext. We expect
            // that the ciphertext is a clean multiple of the block size, and to be non-zero.
            guard let lengthView = source.readSlice(length: 4)?.readableBytesView,
                let ciphertextView = source.readSlice(length: source.readableBytes - 16)?.readableBytesView,
                let tagView = source.readSlice(length: 16)?.readableBytesView,
                ciphertextView.count > 0, ciphertextView.count % Self.cipherBlockSize == 0 else {
                // The only way this fails is if the payload doesn't match this encryption scheme.
                throw NIOSSHError.invalidEncryptedPacketLength
            }

            // Ok, let's try to decrypt this data.
            let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: self.inboundNonce), ciphertext: ciphertextView, tag: tagView)
            plaintext = try AES.GCM.open(sealedBox, using: self.inboundEncryptionKey, authenticating: lengthView)

            // All good! A quick soundness check to verify that the length of the plaintext is ok.
            guard plaintext.count % Self.cipherBlockSize == 0, plaintext.count == ciphertextView.count else {
                throw NIOSSHError.invalidDecryptedPlaintextLength
            }
        }

        // Don't forget to increment the inbound nonce.
        self.inboundNonce.increment()

        // Ok, we want to write the plaintext back into the buffer. This contains the padding length byte and the padding
        // bytes, so we want to strip those. We write back into the buffer and then slice the return value out because
        // it's highly likely that the source buffer is held uniquely, which means we can avoid an allocation.
        try plaintext.removePaddingBytes()
        source.prependData(plaintext)

        // This slice read must succeed, as we just wrote in that many bytes.
        return source.readSlice(length: plaintext.count)!
    }

    func encryptPacket(_ packet: NIOSSHEncryptablePayload, to outboundBuffer: inout ByteBuffer) throws {
        // Keep track of where the length is going to be written.
        let packetLengthIndex = outboundBuffer.writerIndex
        let packetLengthLength = MemoryLayout<UInt32>.size
        let packetPaddingIndex = outboundBuffer.writerIndex + packetLengthLength
        let packetPaddingLength = MemoryLayout<UInt8>.size

        outboundBuffer.moveWriterIndex(forwardBy: packetLengthLength + packetPaddingLength)

        // First, we write the packet.
        let payloadBytes = outboundBuffer.writeEncryptablePayload(packet)

        // Ok, now we need to pad. The rules for padding for AES GCM are:
        //
        // 1. We must pad out such that the total encrypted content (padding length byte,
        //     plus content bytes, plus padding bytes) is a multiple of the block size.
        // 2. At least 4 bytes of padding MUST be added.
        // 3. This padding SHOULD be random.
        //
        // Note that, unlike other protection modes, the length is not encrypted, and so we
        // must exclude it from the padding calculation.
        //
        // So we check how many bytes we've already written, use modular arithmetic to work out
        // how many more bytes we need, and then if that's fewer than 4 we add a block size to it
        // to fill it out.
        var encryptedBufferSize = payloadBytes + packetPaddingLength
        var necessaryPaddingBytes = Self.cipherBlockSize - (encryptedBufferSize % Self.cipherBlockSize)
        if necessaryPaddingBytes < 4 {
            necessaryPaddingBytes += Self.cipherBlockSize
        }

        // We now want to write that many padding bytes to the end of the buffer. These are supposed to be
        // random bytes. We're going to get those from the system random number generator.
        encryptedBufferSize += outboundBuffer.writeSSHPaddingBytes(count: necessaryPaddingBytes)
        precondition(encryptedBufferSize % Self.cipherBlockSize == 0, "Incorrectly counted buffer size; got \(encryptedBufferSize)")

        // We now know the length: it's going to be "encrypted buffer size". The length does not include the tag, so don't add it.
        // Let's write that in. We also need to write the number of padding bytes in.
        outboundBuffer.setInteger(UInt32(encryptedBufferSize), at: packetLengthIndex)
        outboundBuffer.setInteger(UInt8(necessaryPaddingBytes), at: packetPaddingIndex)

        // Ok, nice! Now we need to encrypt the data. We pass the length field as additional authenticated data, and the encrypted
        // payload portion as the data to encrypt. We know these views will be valid, so we forcibly unwrap them: if they're invalid,
        // our math was wrong and we cannot recover.
        let sealedBox = try AES.GCM.seal(outboundBuffer.viewBytes(at: packetPaddingIndex, length: encryptedBufferSize)!,
                                         using: self.outboundEncryptionKey,
                                         nonce: try AES.GCM.Nonce(data: self.outboundNonce),
                                         authenticating: outboundBuffer.viewBytes(at: packetLengthIndex, length: packetLengthLength)!)

        assert(sealedBox.ciphertext.count == encryptedBufferSize)

        // We now want to overwrite the portion of the bytebuffer that contains the plaintext with the ciphertext, and then append the
        // tag.
        outboundBuffer.setContiguousBytes(sealedBox.ciphertext, at: packetPaddingIndex)
        let tagLength = outboundBuffer.writeContiguousBytes(sealedBox.tag)
        precondition(tagLength == self.macBytes, "Unexpected short tag")

        // Now we increment the Nonce for the next use, and then we're done!
        self.outboundNonce.increment()
    }
}

/// An implementation of AES128 GCM in OpenSSH mode.
///
/// The OpenSSH mode of AES128 GCM differs from the RFC 5647 version by not offering a MAC
/// algorithm, and instead by ignoring the result of the MAC negotiation.
///
/// This algorithm does not encrypt the length field, instead encoding it as associated data.
final class AES128GCMOpenSSHTransportProtection: AESGCMTransportProtection {
    override static var cipherName: String {
        "aes128-gcm@openssh.com"
    }

    override static var macName: String? {
        nil
    }

    override static var keySizes: ExpectedKeySizes {
        .init(ivSize: 12, encryptionKeySize: 16, macKeySize: 16)
    }
}

/// An implementation of AES256 GCM in OpenSSH mode.
///
/// The OpenSSH mode of AES256 GCM differs from the RFC 5647 version by not offering a MAC
/// algorithm, and instead by ignoring the result of the MAC negotiation.
///
/// This algorithm does not encrypt the length field, instead encoding it as associated data.
final class AES256GCMOpenSSHTransportProtection: AESGCMTransportProtection {
    override static var cipherName: String {
        "aes256-gcm@openssh.com"
    }

    override static var macName: String? {
        nil
    }

    override static var keySizes: ExpectedKeySizes {
        .init(ivSize: 12, encryptionKeySize: 32, macKeySize: 16)
    }
}

// MARK: - SSHAESGCMNonce

/// A representation of the AES GCM Nonce as a weird hybrid integer for SSH.
///
/// SSH has an awkward requirement that we be able to perform a certain amount of integer math on an
/// AES GCM Nonce. Specifically, we have this, from RFC 5647 § 7.1:
///
/// > With AES-GCM, the 12-octet IV is broken into two fields: a 4-octet
/// > fixed field and an 8-octet invocation counter field.  The invocation
/// > field is treated as a 64-bit integer and is incremented after each
/// > invocation of AES-GCM to process a binary packet.
///
/// Internally we have a few requirements: we'd like to be able to store and manipulate these nonces
/// without heap allocations, and we'd like to be able to quickly create CryptoKit `AES.GCM.Nonce` objects.
/// That requires a slightly custom data structure. Specifically, this custom data structure needs to be able
/// to rapidly vend an interior pointer for the use of the DataProtocol constructor that CryptoKit wants.
///
/// Thus, it must conform to DataProtocol, ContiguousBytes, and therefore also RandomAccessCollection. This is a
/// thoroughly awkward data structure, but we can make it work.
struct SSHAESGCMNonce {
    /// We store the nonce as a tuple of 64-bit integers. This conveniently allows us to access the nonce
    /// via a pointer, which is useful for the DataProtocol conformance we need to easily create AES.GCM.Nonce
    /// types.
    ///
    /// The observant may notice that an AES GCM Nonce is 12 bytes long, but we have 16 bytes here. We avoid
    /// using the leftmost 4 bytes in memory: they should always be zeros.
    private var baseNonceRepresentation: (UInt64, UInt64) = (0, 0)

    init(keyExchangeResult: [UInt8]) throws {
        guard keyExchangeResult.count == 12 else {
            throw NIOSSHError.invalidNonceLength
        }

        withUnsafeMutableBytes(of: &self.baseNonceRepresentation) { reprPointer in
            /// The top 4 bytes are irrelevant.
            let reprPointer = UnsafeMutableRawBufferPointer(rebasing: reprPointer[4...])
            precondition(reprPointer.count == 12)
            reprPointer.copyBytes(from: keyExchangeResult)
        }
    }
}

extension SSHAESGCMNonce {
    mutating func increment() {
        // Here we implement the following requirement from RFC 5647:
        //
        // > With AES-GCM, the 12-octet IV is broken into two fields: a 4-octet
        // > fixed field and an 8-octet invocation counter field.  The invocation
        // > field is treated as a 64-bit integer and is incremented after each
        // > invocation of AES-GCM to process a binary packet.
        //
        // Note that we have to do this in network byte order. Thus, the 8 octet invocation
        // counter field is currently sitting in the second UInt64 in the tuple, but note that
        // it is stored there in *network byte order*. To make the addition work, we need to do
        // some endianness swaps.
        //
        // One final note: overflow is expected and allowed in this addition.
        self.baseNonceRepresentation.1 = (UInt64(bigEndian: self.baseNonceRepresentation.1) &+ 1).bigEndian
    }
}

// MARK: RandomAccessCollection conformace

extension SSHAESGCMNonce: RandomAccessCollection {
    struct Index: Strideable, Comparable, Hashable {
        fileprivate var offset: Int

        init(fromOffset offset: Int) {
            self.offset = offset
        }

        func advanced(by n: Int) -> SSHAESGCMNonce.Index {
            Index(fromOffset: self.offset + n)
        }

        func distance(to other: SSHAESGCMNonce.Index) -> Int {
            other.offset - self.offset
        }

        static func < (lhs: SSHAESGCMNonce.Index, rhs: SSHAESGCMNonce.Index) -> Bool {
            lhs.offset < rhs.offset
        }
    }

    var startIndex: SSHAESGCMNonce.Index {
        Index(fromOffset: 4)
    }

    var endIndex: SSHAESGCMNonce.Index {
        Index(fromOffset: 16)
    }

    subscript(position: SSHAESGCMNonce.Index) -> UInt8 {
        precondition(position.offset >= 4 && position.offset < MemoryLayout.size(ofValue: self.baseNonceRepresentation), "Invalid index!")

        return Swift.withUnsafeBytes(of: self.baseNonceRepresentation) { reprPointer in
            reprPointer[position.offset]
        }
    }

    func index(after i: SSHAESGCMNonce.Index) -> SSHAESGCMNonce.Index {
        Index(fromOffset: i.offset + 1)
    }
}

// MARK: ContiguousBytes conformance

extension SSHAESGCMNonce: ContiguousBytes {
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Swift.withUnsafeBytes(of: self.baseNonceRepresentation) { reprPointer in
            let reprPointer = UnsafeRawBufferPointer(rebasing: reprPointer[4...])
            return try body(reprPointer)
        }
    }
}

// MARK: DataProtocol conformance

extension SSHAESGCMNonce: DataProtocol {
    var regions: CollectionOfOne<SSHAESGCMNonce> {
        .init(self)
    }
}

extension ByteBuffer {
    /// Prepends the given Data to this ByteBuffer.
    ///
    /// Will crash if there isn't space in the front of this buffer, so please ensure there is!
    fileprivate mutating func prependData(_ data: Data) {
        self.moveReaderIndex(to: self.readerIndex - data.count)
        self.setContiguousBytes(data, at: self.readerIndex)
    }
}

extension Data {
    /// Removes the padding bytes from a Data object.
    fileprivate mutating func removePaddingBytes() throws {
        guard let paddingLength = self.first, paddingLength >= 4 else {
            throw NIOSSHError.insufficientPadding
        }

        // We're going to slice out the content bytes. To do that, can simply find the end index of the content, and confirm it's
        // not walked off the front of the buffer. If it has, there's too much padding and an error has occurred.
        let contentStartIndex = self.index(after: self.startIndex)
        guard let contentEndIndex = self.index(self.endIndex, offsetBy: -Int(paddingLength), limitedBy: contentStartIndex) else {
            throw NIOSSHError.excessPadding
        }

        self = self[contentStartIndex ..< contentEndIndex]
    }
}
