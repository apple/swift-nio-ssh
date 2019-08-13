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

import XCTest
import NIO
import CryptoKit
@testable import NIOSSH


final class HostKeyTests: XCTestCase {
    func testBasicEd25519SigningFlow() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHHostPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testBasicECDSAP256SigningFlow() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let sshKey = NIOSSHHostPrivateKey(p256Key: ecdsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testEd25519FailsVerificationWithDifferentKeys() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHHostPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHHostPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP256FailsVerificationWithDifferentKeys() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let sshKey = NIOSSHHostPrivateKey(p256Key: ecdsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHHostPrivateKey(p256Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testEd25519FailsVerificationWithWrongAlgorithms() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHHostPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHHostPrivateKey(p256Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP256FailsVerificationWithWrongAlgorithms() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let sshKey = NIOSSHHostPrivateKey(p256Key: ecdsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHHostPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testUnrecognisedKey() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ssh-rsa".utf8)

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .unknownPublicKey)
        }
    }

    func testInvalidDomainParametersForECDSAP256() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ecdsa-sha2-nistp256".utf8)
        buffer.writeSSHString("nistp384".utf8) // Surprise!

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidDomainParametersForKey)
        }
    }

    func testUnrecognisedSignature() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ssh-rsa".utf8)

        XCTAssertThrowsError(try buffer.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .unknownSignature)
        }
    }
}
