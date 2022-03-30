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
import NIOCore
@testable import NIOSSH
import XCTest

func assertNoThrowWithValue<T>(_ body: @autoclosure () throws -> T, defaultValue: T? = nil, message: String? = nil, file: StaticString = #file, line: UInt = #line) throws -> T {
    do {
        return try body()
    } catch {
        XCTFail("\(message.map { $0 + ": " } ?? "")unexpected error \(error) thrown", file: file, line: line)
        if let defaultValue = defaultValue {
            return defaultValue
        } else {
            throw error
        }
    }
}

// This algorithm is not secure, used only for testing purposes
struct InsecureEncryptionAlgorithm {
    static func encrypt(key: ByteBuffer, plaintext: ByteBuffer) -> ByteBuffer {
        var ciphertext = ByteBuffer()
        var plaintext = plaintext
        var key = key
        guard let k0 = key.readInteger(as: UInt32.self),
            let k1 = key.readInteger(as: UInt32.self),
            let k2 = key.readInteger(as: UInt32.self),
            let k3 = key.readInteger(as: UInt32.self) else {
            preconditionFailure("check key size")
        }

        while var block = plaintext.readSlice(length: 16) {
            guard var v0 = block.readInteger(as: UInt32.self),
                var v1 = block.readInteger(as: UInt32.self),
                var v2 = block.readInteger(as: UInt32.self),
                var v3 = block.readInteger(as: UInt32.self) else {
                preconditionFailure("check block size")
            }

            v0 = v0 ^ k0
            v1 = v1 ^ k1
            v2 = v2 ^ k2
            v3 = v3 ^ k3

            ciphertext.writeInteger(v0)
            ciphertext.writeInteger(v1)
            ciphertext.writeInteger(v2)
            ciphertext.writeInteger(v3)
        }
        return ciphertext
    }

    static func decrypt(key: ByteBuffer, ciphertext: ByteBuffer) -> ByteBuffer {
        var plaintext = ByteBuffer()
        var ciphertext = ciphertext
        var key = key
        guard let k0 = key.readInteger(as: UInt32.self),
            let k1 = key.readInteger(as: UInt32.self),
            let k2 = key.readInteger(as: UInt32.self),
            let k3 = key.readInteger(as: UInt32.self) else {
            preconditionFailure("check key size")
        }

        while var block = ciphertext.readSlice(length: 16) {
            guard var v0 = block.readInteger(as: UInt32.self),
                var v1 = block.readInteger(as: UInt32.self),
                var v2 = block.readInteger(as: UInt32.self),
                var v3 = block.readInteger(as: UInt32.self) else {
                preconditionFailure("check block size")
            }

            v0 = v0 ^ k0
            v1 = v1 ^ k1
            v2 = v2 ^ k2
            v3 = v3 ^ k3

            plaintext.writeInteger(v0)
            plaintext.writeInteger(v1)
            plaintext.writeInteger(v2)
            plaintext.writeInteger(v3)
        }

        return plaintext
    }
}

class TestTransportProtection: NIOSSHTransportProtection {
    enum TestError: Error {
        case doubleDecode
    }

    static var cipherBlockSize: Int {
        16
    }

    var macBytes: Int {
        32
    }

    static var cipherName: String {
        "insecure-tiny-encription-cipher"
    }

    static var macName: String? {
        nil
    }

    static var keySizes: ExpectedKeySizes {
        .init(ivSize: 12, encryptionKeySize: 16, macKeySize: 16)
    }

    private var outboundEncryptionKey: ByteBuffer
    private var inboundEncryptionKey: ByteBuffer
    private var outboundMACKey: SymmetricKey
    private var inboundMACKey: SymmetricKey

    private var lastFirstBlock: ByteBufferView?

    required init(initialKeys: NIOSSHSessionKeys) {
        precondition(initialKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        precondition(initialKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        self.outboundEncryptionKey = initialKeys.outboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.inboundEncryptionKey = initialKeys.inboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.outboundMACKey = initialKeys.outboundMACKey
        self.inboundMACKey = initialKeys.inboundMACKey
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        precondition(newKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        precondition(newKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        self.outboundEncryptionKey = newKeys.outboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.inboundEncryptionKey = newKeys.inboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.outboundMACKey = newKeys.outboundMACKey
        self.inboundMACKey = newKeys.inboundMACKey
    }

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        let index = source.readerIndex

        guard let ciphertextView = source.viewBytes(at: index, length: Self.cipherBlockSize),
            ciphertextView.count > 0, ciphertextView.count % Self.cipherBlockSize == 0 else {
            // The only way this fails is if the payload doesn't match this encryption scheme.
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        if self.lastFirstBlock == ciphertextView {
            throw TestError.doubleDecode
        }

        self.lastFirstBlock = ciphertextView

        let plaintext = InsecureEncryptionAlgorithm.decrypt(key: self.inboundEncryptionKey, ciphertext: ByteBuffer(bytes: ciphertextView))

        source.setBytes(plaintext.readableBytesView, at: index)
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer) throws -> ByteBuffer {
        defer {
            self.lastFirstBlock = nil
        }

        guard var plaintext = source.readSlice(length: Self.cipherBlockSize) else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        // First block is expected to be decoded by decodeFirstBlock
        if source.readableBytes > self.macBytes {
            guard let ciphertext = source.readSlice(length: source.readableBytes - 32),
                ciphertext.readableBytes > 0, ciphertext.readableBytes % Self.cipherBlockSize == 0 else {
                // The only way this fails is if the payload doesn't match this encryption scheme.
                throw NIOSSHError.invalidEncryptedPacketLength
            }

            var tail = InsecureEncryptionAlgorithm.decrypt(key: self.inboundEncryptionKey, ciphertext: ciphertext)
            plaintext.writeBuffer(&tail)
        }

        guard let tagView = source.readSlice(length: 32)?.readableBytesView else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        guard HMAC<SHA256>.isValidAuthenticationCode(tagView, authenticating: plaintext.readableBytesView, using: self.inboundMACKey) else {
            preconditionFailure("authentication failure")
        }

        // First 4 bytes are length
        plaintext.moveReaderIndex(forwardBy: 4)
        let paddingLength = plaintext.readInteger(as: UInt8.self)!
        return plaintext.readSlice(length: plaintext.readableBytes - Int(paddingLength))!
    }

    func encryptPacket(_ packet: NIOSSHEncryptablePayload, to outboundBuffer: inout ByteBuffer) throws {
        let packetLengthIndex = outboundBuffer.writerIndex
        let packetLengthLength = MemoryLayout<UInt32>.size
        let packetPaddingIndex = outboundBuffer.writerIndex + packetLengthLength
        let packetPaddingLength = MemoryLayout<UInt8>.size

        outboundBuffer.moveWriterIndex(forwardBy: packetLengthLength + packetPaddingLength)

        let payloadBytes = outboundBuffer.writeEncryptablePayload(packet)

        var encryptedBufferSize = payloadBytes + packetPaddingLength + packetLengthLength
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
        outboundBuffer.setInteger(UInt32(encryptedBufferSize - packetLengthLength), at: packetLengthIndex)
        outboundBuffer.setInteger(UInt8(necessaryPaddingBytes), at: packetPaddingIndex)
        let plaintextView = outboundBuffer.viewBytes(at: packetLengthIndex, length: encryptedBufferSize)!
        let ciphertext = InsecureEncryptionAlgorithm.encrypt(key: self.outboundEncryptionKey, plaintext: ByteBuffer(bytes: plaintextView))
        assert(ciphertext.readableBytes == encryptedBufferSize)

        var hmac = HMAC<SHA256>.init(key: self.outboundMACKey)
        hmac.update(data: plaintextView)

        // We now want to overwrite the portion of the bytebuffer that contains the plaintext with the ciphertext, and then append the tag.
        outboundBuffer.setBytes(ciphertext.readableBytesView, at: packetLengthIndex)
        let tagLength = outboundBuffer.writeBytes(hmac.finalize())
        precondition(tagLength == self.macBytes, "Unexpected short tag")
    }
}
