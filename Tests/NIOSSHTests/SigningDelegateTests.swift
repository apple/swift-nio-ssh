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
import NIOCore
import NIOFoundationCompat
import XCTest

@testable import NIOSSH

final class SigningDelegateTests: XCTestCase {
    /// Build a representative user-authentication signable payload for a public key.
    private func makePayload(for publicKey: NIOSSHPublicKey) -> UserAuthSignablePayload {
        var sessionIdentifier = ByteBufferAllocator().buffer(capacity: 32)
        sessionIdentifier.writeBytes(Array(repeating: UInt8(0x2A), count: 32))
        return UserAuthSignablePayload(
            sessionIdentifier: sessionIdentifier,
            userName: "user",
            serviceName: "ssh-connection",
            publicKey: publicKey
        )
    }

    func testBasicEd25519SigningDelegateFlow() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(ed25519Key: edKey).publicKey

        let payload = self.makePayload(for: publicKey)
        let rawSignature = try edKey.signature(for: payload.bytes.readableBytesView)
        let delegateSignature = NIOSSHSignature.ed25519(signature: Data(rawSignature))
        let sshKey = NIOSSHPrivateKey(publicKey: publicKey) { _ in delegateSignature }

        let signature = try assertNoThrowWithValue(sshKey.sign(payload))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(publicKey.isValidSignature(signature, for: payload)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(publicKey.isValidSignature(newSignature, for: payload)))
    }

    func testBasicECDSAP256SigningDelegateFlow() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(p256Key: ecdsaKey).publicKey

        let payload = self.makePayload(for: publicKey)
        let rawSignature = try ecdsaKey.signature(for: Data(payload.bytes.readableBytesView))
        let delegateSignature = try NIOSSHSignature.ecdsaP256(signature: Data(rawSignature.rawRepresentation))
        let sshKey = NIOSSHPrivateKey(publicKey: publicKey) { _ in delegateSignature }

        let signature = try assertNoThrowWithValue(sshKey.sign(payload))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(publicKey.isValidSignature(signature, for: payload)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(publicKey.isValidSignature(newSignature, for: payload)))
    }

    func testBasicECDSAP384SigningDelegateFlow() throws {
        let ecdsaKey = P384.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(p384Key: ecdsaKey).publicKey

        let payload = self.makePayload(for: publicKey)
        let rawSignature = try ecdsaKey.signature(for: Data(payload.bytes.readableBytesView))
        let delegateSignature = try NIOSSHSignature.ecdsaP384(signature: Data(rawSignature.rawRepresentation))
        let sshKey = NIOSSHPrivateKey(publicKey: publicKey) { _ in delegateSignature }

        let signature = try assertNoThrowWithValue(sshKey.sign(payload))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(publicKey.isValidSignature(signature, for: payload)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(publicKey.isValidSignature(newSignature, for: payload)))
    }

    func testBasicECDSAP521SigningDelegateFlow() throws {
        let ecdsaKey = P521.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(p521Key: ecdsaKey).publicKey

        let payload = self.makePayload(for: publicKey)
        let rawSignature = try ecdsaKey.signature(for: Data(payload.bytes.readableBytesView))
        let delegateSignature = try NIOSSHSignature.ecdsaP521(signature: Data(rawSignature.rawRepresentation))
        let sshKey = NIOSSHPrivateKey(publicKey: publicKey) { _ in delegateSignature }

        let signature = try assertNoThrowWithValue(sshKey.sign(payload))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(publicKey.isValidSignature(signature, for: payload)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(publicKey.isValidSignature(newSignature, for: payload)))
    }

    func testSigningDelegateFailsVerificationWithDifferentKey() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(ed25519Key: edKey).publicKey

        let payload = self.makePayload(for: publicKey)
        let rawSignature = try edKey.signature(for: payload.bytes.readableBytesView)
        let delegateSignature = NIOSSHSignature.ed25519(signature: Data(rawSignature))
        let sshKey = NIOSSHPrivateKey(publicKey: publicKey) { _ in delegateSignature }

        let signature = try assertNoThrowWithValue(sshKey.sign(payload))

        let otherPublicKey = NIOSSHPrivateKey(ed25519Key: .init()).publicKey

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherPublicKey.isValidSignature(signature, for: payload)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherPublicKey.isValidSignature(newSignature, for: payload)))
    }

    func testSigningDelegatePassesSignablePayload() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let publicKey = NIOSSHPrivateKey(ed25519Key: edKey).publicKey

        let payload = self.makePayload(for: publicKey)
        let rawSignature = try edKey.signature(for: payload.bytes.readableBytesView)
        let delegateSignature = NIOSSHSignature.ed25519(signature: Data(rawSignature))

        let recorder = PayloadRecorder()
        let sshKey = NIOSSHPrivateKey(publicKey: publicKey) { received in
            recorder.bytes = Array(received)
            return delegateSignature
        }

        _ = try assertNoThrowWithValue(sshKey.sign(payload))

        XCTAssertEqual(recorder.bytes, Array(payload.bytes.readableBytesView))
    }

    func testSigningDelegateExposesPublicKey() throws {
        let publicKey = NIOSSHPrivateKey(ed25519Key: .init()).publicKey
        let sshKey = NIOSSHPrivateKey(publicKey: publicKey) { _ in
            .ed25519(signature: Data())
        }

        XCTAssertEqual(sshKey.publicKey, publicKey)
    }

    func testSigningDelegatePropagatesErrors() throws {
        struct SigningFailure: Error {}

        let publicKey = NIOSSHPrivateKey(ed25519Key: .init()).publicKey
        let sshKey = NIOSSHPrivateKey(publicKey: publicKey) { _ in
            throw SigningFailure()
        }

        let payload = self.makePayload(for: publicKey)
        XCTAssertThrowsError(try sshKey.sign(payload)) { error in
            XCTAssertTrue(error is SigningFailure)
        }
    }
}

/// Records the payload bytes handed to a signing delegate so a test can assert
/// that the callback received the expected ``UserAuthSignablePayload`` content.
private final class PayloadRecorder: @unchecked Sendable {
    var bytes: [UInt8]?
}
