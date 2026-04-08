//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOConcurrencyHelpers
import NIOCore
@testable import NIOSSH
import XCTest

final class NIOSSHExternalSignerTests: XCTestCase {
    func testExternalSignerUsedAndSignaturePlumbed() throws {
        let ed25519Key = Curve25519.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(ed25519Key: ed25519Key).publicKey
        let signatureBytes: [UInt8] = [0xAA, 0xBB, 0xCC]
        let signer = RecordingSigner(publicKey: publicKey, signatureBytes: signatureBytes)

        let privateKey = NIOSSHPrivateKey(externalSigner: signer)
        let payload = makePayload(publicKey: publicKey)
        let signature = try privateKey.sign(payload)

        XCTAssertEqual(signer.callCount, 1)
        XCTAssertEqual(signer.lastPayloadBytes, Array(payload.bytes.readableBytesView))

        var expectedSignatureBuffer = ByteBufferAllocator().buffer(capacity: signatureBytes.count)
        expectedSignatureBuffer.writeBytes(signatureBytes)
        let expected = NIOSSHSignature(backingSignature: .ed25519(.byteBuffer(expectedSignatureBuffer)))
        XCTAssertEqual(signature, expected)
    }

    func testExternalSignerP256UsedAndSignaturePlumbed() throws {
        let p256Key = P256.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(p256Key: p256Key).publicKey
        let signature = try p256Key.signature(for: Data([0x01, 0x02, 0x03, 0x04]))
        let signer = RecordingSigner(
            publicKey: publicKey,
            signatureBytes: Array(signature.rawRepresentation)
        )

        let privateKey = NIOSSHPrivateKey(externalSigner: signer)
        let payload = makePayload(publicKey: publicKey)
        let producedSignature = try privateKey.sign(payload)

        XCTAssertEqual(signer.callCount, 1)
        let expected = NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        XCTAssertEqual(producedSignature, expected)
    }

    func testExternalSignerP256InvalidRawSignatureThrows() throws {
        let p256Key = P256.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(p256Key: p256Key).publicKey
        let signer = RecordingSigner(publicKey: publicKey, signatureBytes: [0x01, 0x02, 0x03])
        let privateKey = NIOSSHPrivateKey(externalSigner: signer)
        let payload = makePayload(publicKey: publicKey)

        XCTAssertThrowsError(try privateKey.sign(payload))
    }

    func testExternalSignerP384UsedAndSignaturePlumbed() throws {
        let p384Key = P384.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(p384Key: p384Key).publicKey
        let signature = try p384Key.signature(for: Data([0x05, 0x06, 0x07, 0x08]))
        let signer = RecordingSigner(
            publicKey: publicKey,
            signatureBytes: Array(signature.rawRepresentation)
        )

        let privateKey = NIOSSHPrivateKey(externalSigner: signer)
        let payload = makePayload(publicKey: publicKey)
        let producedSignature = try privateKey.sign(payload)

        XCTAssertEqual(signer.callCount, 1)
        let expected = NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        XCTAssertEqual(producedSignature, expected)
    }

    func testExternalSignerP384InvalidRawSignatureThrows() throws {
        let p384Key = P384.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(p384Key: p384Key).publicKey
        let signer = RecordingSigner(publicKey: publicKey, signatureBytes: [0x01, 0x02, 0x03])
        let privateKey = NIOSSHPrivateKey(externalSigner: signer)
        let payload = makePayload(publicKey: publicKey)

        XCTAssertThrowsError(try privateKey.sign(payload))
    }

    func testExternalSignerP521UsedAndSignaturePlumbed() throws {
        let p521Key = P521.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(p521Key: p521Key).publicKey
        let signature = try p521Key.signature(for: Data([0x09, 0x0A, 0x0B, 0x0C]))
        let signer = RecordingSigner(
            publicKey: publicKey,
            signatureBytes: Array(signature.rawRepresentation)
        )

        let privateKey = NIOSSHPrivateKey(externalSigner: signer)
        let payload = makePayload(publicKey: publicKey)
        let producedSignature = try privateKey.sign(payload)

        XCTAssertEqual(signer.callCount, 1)
        let expected = NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        XCTAssertEqual(producedSignature, expected)
    }

    func testExternalSignerP521InvalidRawSignatureThrows() throws {
        let p521Key = P521.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(p521Key: p521Key).publicKey
        let signer = RecordingSigner(publicKey: publicKey, signatureBytes: [0x01, 0x02, 0x03])
        let privateKey = NIOSSHPrivateKey(externalSigner: signer)
        let payload = makePayload(publicKey: publicKey)

        XCTAssertThrowsError(try privateKey.sign(payload))
    }

    private func makePayload(publicKey: NIOSSHPublicKey) -> UserAuthSignablePayload {
        var sessionID = ByteBufferAllocator().buffer(capacity: 16)
        sessionID.writeBytes([0x01, 0x02, 0x03, 0x04])
        return UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: "user",
            serviceName: "ssh-connection",
            publicKey: publicKey
        )
    }
}

private struct RecordingSigner: NIOSSHExternalSigner {
    let publicKey: NIOSSHPublicKey
    let signatureBytes: [UInt8]
    private let payloadBytes = NIOLockedValueBox<[UInt8]?>(nil)
    private let count = NIOLockedValueBox<Int>(0)

    var callCount: Int {
        count.withLockedValue { $0 }
    }

    var lastPayloadBytes: [UInt8]? {
        payloadBytes.withLockedValue { $0 }
    }

    func sign(payload: ByteBuffer) throws -> ByteBuffer {
        payloadBytes.withLockedValue { $0 = Array(payload.readableBytesView) }
        count.withLockedValue { $0 += 1 }
        var buffer = ByteBufferAllocator().buffer(capacity: signatureBytes.count)
        buffer.writeBytes(signatureBytes)
        return buffer
    }
}
