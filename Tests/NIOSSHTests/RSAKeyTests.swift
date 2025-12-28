//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019-2025 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
@_spi(CryptoExtras) import _CryptoExtras
import NIOCore
import NIOFoundationCompat
import XCTest

@testable import NIOSSH

final class RSAKeyTests: XCTestCase {
    // MARK: - Basic Signing Flow Tests (matching pattern from HostKeyTests)

    func testBasicRSASHA512SigningFlow() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        let digest = SHA512.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testBasicRSASHA256SigningFlow() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Verify that a signature over a SHA256 digest can be validated (algorithm selection is tested below)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))
    }

    // MARK: - RSA Signature Algorithm Selection Tests

    func testRSASignatureAlgorithmSHA512() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)

        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: "testuser",
            serviceName: "ssh-connection",
            publicKey: sshKey.publicKey,
            rsaSignatureAlgorithm: .sha512
        )

        let signature = try assertNoThrowWithValue(sshKey.sign(payload, rsaSignatureAlgorithm: .sha512))
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: payload)))

        // Verify round-trip
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)
        let roundTripped = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(roundTripped, for: payload)))
    }

    func testRSASignatureAlgorithmSHA256() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)

        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: "testuser",
            serviceName: "ssh-connection",
            publicKey: sshKey.publicKey,
            rsaSignatureAlgorithm: .sha256
        )

        let signature = try assertNoThrowWithValue(sshKey.sign(payload, rsaSignatureAlgorithm: .sha256))
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: payload)))

        // Verify round-trip
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)
        let roundTripped = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(roundTripped, for: payload)))
    }

    func testRSASignatureAlgorithmSHA1() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)

        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: "testuser",
            serviceName: "ssh-connection",
            publicKey: sshKey.publicKey,
            rsaSignatureAlgorithm: .sha1
        )

        let signature = try assertNoThrowWithValue(sshKey.sign(payload, rsaSignatureAlgorithm: .sha1))
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: payload)))

        // Verify round-trip
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)
        let roundTripped = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(roundTripped, for: payload)))
    }

    // MARK: - Verification Failure Tests

    func testRSAFailsVerificationWithDifferentKeys() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        let digest = SHA512.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherRSAKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let otherSSHKey = NIOSSHPrivateKey(rsaKey: otherRSAKey)

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testRSAFailsVerificationWithWrongAlgorithmKeys() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        let digest = SHA512.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Try verifying with an Ed25519 key
        let otherSSHKey = NIOSSHPrivateKey(ed25519Key: .init())

        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))
    }

    func testEd25519FailsVerificationWithRSASignature() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let rsaSSHKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        // RSA key should not verify Ed25519 signature
        XCTAssertNoThrow(XCTAssertFalse(rsaSSHKey.publicKey.isValidSignature(signature, for: digest)))
    }

    // MARK: - Public Key Wire Format Tests

    func testRSAPublicKeyRoundTrip() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)
        let publicKey = sshKey.publicKey

        // Write to buffer
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHHostKey(publicKey)

        // Read back
        let readKey = try assertNoThrowWithValue(buffer.readSSHHostKey()!)

        // Keys should be equal
        XCTAssertEqual(publicKey, readKey)
    }

    func testRSAPublicKeyPrefix() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        XCTAssertTrue(sshKey.publicKey.keyPrefix.elementsEqual("ssh-rsa".utf8))
    }

    // MARK: - Host Key Algorithm Tests

    func testRSAHostKeyAlgorithms() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        let algorithms = sshKey.hostKeyAlgorithms
        XCTAssertEqual(algorithms.count, 3)
        XCTAssertTrue(algorithms.contains("rsa-sha2-512"))
        XCTAssertTrue(algorithms.contains("rsa-sha2-256"))
        XCTAssertTrue(algorithms.contains("ssh-rsa"))
    }

    // MARK: - RSASignatureAlgorithm Enum Tests

    func testRSASignatureAlgorithmFallback() {
        XCTAssertEqual(RSASignatureAlgorithm.sha512.fallback, .sha256)
        XCTAssertEqual(RSASignatureAlgorithm.sha256.fallback, .sha1)
        XCTAssertNil(RSASignatureAlgorithm.sha1.fallback)
    }

    func testRSASignatureAlgorithmWireNames() {
        XCTAssertEqual(RSASignatureAlgorithm.sha512.algorithmName, "rsa-sha2-512")
        XCTAssertEqual(RSASignatureAlgorithm.sha256.algorithmName, "rsa-sha2-256")
        XCTAssertEqual(RSASignatureAlgorithm.sha1.algorithmName, "ssh-rsa")
    }

    // MARK: - Different Key Sizes

    func testRSA2048KeyWorks() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        let digest = SHA512.hash(data: Array("test".utf8))
        let signature = try sshKey.sign(digest: digest)

        XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest))
    }

    func testRSA3072KeyWorks() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits3072)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        let digest = SHA512.hash(data: Array("test".utf8))
        let signature = try sshKey.sign(digest: digest)

        XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest))
    }

    func testRSA4096KeyWorks() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits4096)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        let digest = SHA512.hash(data: Array("test".utf8))
        let signature = try sshKey.sign(digest: digest)

        XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest))
    }

    // MARK: - Signature Wire Format Tests

    func testRSASHA512SignaturePrefix() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)

        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: "testuser",
            serviceName: "ssh-connection",
            publicKey: sshKey.publicKey,
            rsaSignatureAlgorithm: .sha512
        )

        let signature = try sshKey.sign(payload, rsaSignatureAlgorithm: .sha512)

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        // Read back the algorithm prefix
        guard let prefixLength = buffer.readInteger(as: UInt32.self),
              let prefixBytes = buffer.readBytes(length: Int(prefixLength)) else {
            XCTFail("Failed to read signature prefix")
            return
        }

        XCTAssertEqual(String(bytes: prefixBytes, encoding: .utf8), "rsa-sha2-512")
    }

    func testRSASHA256SignaturePrefix() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)

        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: "testuser",
            serviceName: "ssh-connection",
            publicKey: sshKey.publicKey,
            rsaSignatureAlgorithm: .sha256
        )

        let signature = try sshKey.sign(payload, rsaSignatureAlgorithm: .sha256)

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        // Read back the algorithm prefix
        guard let prefixLength = buffer.readInteger(as: UInt32.self),
              let prefixBytes = buffer.readBytes(length: Int(prefixLength)) else {
            XCTFail("Failed to read signature prefix")
            return
        }

        XCTAssertEqual(String(bytes: prefixBytes, encoding: .utf8), "rsa-sha2-256")
    }

    func testRSASHA1SignaturePrefix() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)

        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: "testuser",
            serviceName: "ssh-connection",
            publicKey: sshKey.publicKey,
            rsaSignatureAlgorithm: .sha1
        )

        let signature = try sshKey.sign(payload, rsaSignatureAlgorithm: .sha1)

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        // Read back the algorithm prefix
        guard let prefixLength = buffer.readInteger(as: UInt32.self),
              let prefixBytes = buffer.readBytes(length: Int(prefixLength)) else {
            XCTFail("Failed to read signature prefix")
            return
        }

        XCTAssertEqual(String(bytes: prefixBytes, encoding: .utf8), "ssh-rsa")
    }

    // MARK: - Hashable/Equatable Tests

    func testRSAPublicKeyEquatable() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        // Same key should be equal
        XCTAssertEqual(sshKey.publicKey, sshKey.publicKey)

        // Different key should not be equal
        let otherRSAKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let otherSSHKey = NIOSSHPrivateKey(rsaKey: otherRSAKey)
        XCTAssertNotEqual(sshKey.publicKey, otherSSHKey.publicKey)
    }

    func testRSAPublicKeyHashable() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        var set = Set<NIOSSHPublicKey>()
        set.insert(sshKey.publicKey)

        XCTAssertTrue(set.contains(sshKey.publicKey))

        let otherRSAKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let otherSSHKey = NIOSSHPrivateKey(rsaKey: otherRSAKey)
        XCTAssertFalse(set.contains(otherSSHKey.publicKey))
    }
}
