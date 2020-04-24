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
import NIO
@testable import NIOSSH
import XCTest

final class Curve25519KeyExchangeTests: XCTestCase {
    private func keyExchangeAgreed(_ first: KeyExchangeResult, _ second: KeyExchangeResult) {
        XCTAssertEqual(first.sessionID, second.sessionID)
        XCTAssertEqual(first.keys.initialInboundIV, second.keys.initialOutboundIV)
        XCTAssertEqual(first.keys.initialOutboundIV, second.keys.initialInboundIV)
        XCTAssertEqual(first.keys.inboundEncryptionKey, second.keys.outboundEncryptionKey)
        XCTAssertEqual(first.keys.outboundEncryptionKey, second.keys.inboundEncryptionKey)
        XCTAssertEqual(first.keys.inboundMACKey, second.keys.outboundMACKey)
        XCTAssertEqual(first.keys.outboundMACKey, second.keys.inboundMACKey)
    }

    private func keyExchangeFailed(_ first: KeyExchangeResult, _ second: KeyExchangeResult) {
        // If key exchange fails, we assert that no secrets match. This is a slightly excessive test, but it'll probably be fine.
        XCTAssertNotEqual(first.sessionID, second.sessionID)
        XCTAssertNotEqual(first.keys.initialInboundIV, second.keys.initialOutboundIV)
        XCTAssertNotEqual(first.keys.initialOutboundIV, second.keys.initialInboundIV)
        XCTAssertNotEqual(first.keys.inboundEncryptionKey, second.keys.outboundEncryptionKey)
        XCTAssertNotEqual(first.keys.outboundEncryptionKey, second.keys.inboundEncryptionKey)
        XCTAssertNotEqual(first.keys.inboundMACKey, second.keys.outboundMACKey)
        XCTAssertNotEqual(first.keys.outboundMACKey, second.keys.inboundMACKey)
    }

    func testBasicSuccessfulKeyExchangeNoPreviousSession() throws {
        var server = Curve25519KeyExchange(ourRole: .server([.init(ed25519Key: .init())]), previousSessionIdentifier: nil)
        var client = Curve25519KeyExchange(ourRole: .client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(clientKeyExchangeMessage: clientMessage,
                                                     serverHostKey: serverHostKey,
                                                     initialExchangeBytes: &initialExchangeBytes,
                                                     allocator: ByteBufferAllocator(),
                                                     expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(serverKeyExchangeMessage: serverResponse,
                                                       initialExchangeBytes: &initialExchangeBytes,
                                                       allocator: ByteBufferAllocator(),
                                                       expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testBasicSuccessfulKeyExchangeWithPreviousSession() throws {
        var previousSessionIdentifier = ByteBufferAllocator().buffer(capacity: 1024)
        previousSessionIdentifier.writeBytes(0 ... 255)

        var server = Curve25519KeyExchange(ourRole: .server([.init(ed25519Key: .init())]), previousSessionIdentifier: previousSessionIdentifier)
        var client = Curve25519KeyExchange(ourRole: .client, previousSessionIdentifier: previousSessionIdentifier)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(clientKeyExchangeMessage: clientMessage,
                                                     serverHostKey: serverHostKey,
                                                     initialExchangeBytes: &initialExchangeBytes,
                                                     allocator: ByteBufferAllocator(),
                                                     expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(serverKeyExchangeMessage: serverResponse,
                                                       initialExchangeBytes: &initialExchangeBytes,
                                                       allocator: ByteBufferAllocator(),
                                                       expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testKeyExchangeWithECDSASignatures() throws {
        var server = Curve25519KeyExchange(ourRole: .server([.init(ed25519Key: .init())]), previousSessionIdentifier: nil)
        var client = Curve25519KeyExchange(ourRole: .client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(p256Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(clientKeyExchangeMessage: clientMessage,
                                                     serverHostKey: serverHostKey,
                                                     initialExchangeBytes: &initialExchangeBytes,
                                                     allocator: ByteBufferAllocator(),
                                                     expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(serverKeyExchangeMessage: serverResponse,
                                                       initialExchangeBytes: &initialExchangeBytes,
                                                       allocator: ByteBufferAllocator(),
                                                       expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testBasicSuccessfulKeyExchangeWithWiderKeys() throws {
        var server = Curve25519KeyExchange(ourRole: .server([.init(ed25519Key: .init())]), previousSessionIdentifier: nil)
        var client = Curve25519KeyExchange(ourRole: .client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(clientKeyExchangeMessage: clientMessage,
                                                     serverHostKey: serverHostKey,
                                                     initialExchangeBytes: &initialExchangeBytes,
                                                     allocator: ByteBufferAllocator(),
                                                     expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes)
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(serverKeyExchangeMessage: serverResponse,
                                                       initialExchangeBytes: &initialExchangeBytes,
                                                       allocator: ByteBufferAllocator(),
                                                       expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes)
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testDisagreeingOnInitialExchangeBytesLeadsToFailedKeyExchange() throws {
        var server = Curve25519KeyExchange(ourRole: .server([.init(ed25519Key: .init())]), previousSessionIdentifier: nil)
        var client = Curve25519KeyExchange(ourRole: .client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var serverInitialBytes = ByteBufferAllocator().buffer(capacity: 1024)
        var clientInitialBytes = serverInitialBytes

        serverInitialBytes.writeBytes(0 ..< 128)
        clientInitialBytes.writeBytes(1 ..< 129)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (_, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(clientKeyExchangeMessage: clientMessage,
                                                     serverHostKey: serverHostKey,
                                                     initialExchangeBytes: &serverInitialBytes,
                                                     allocator: ByteBufferAllocator(),
                                                     expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        )

        XCTAssertThrowsError(
            try client.receiveServerKeyExchangePayload(serverKeyExchangeMessage: serverResponse,
                                                       initialExchangeBytes: &clientInitialBytes,
                                                       allocator: ByteBufferAllocator(),
                                                       expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidExchangeHashSignature)
        }
    }

    func testWeValidateTheExchangeHash() throws {
        var server = Curve25519KeyExchange(ourRole: .server([.init(ed25519Key: .init())]), previousSessionIdentifier: nil)
        var client = Curve25519KeyExchange(ourRole: .client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        var (_, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(clientKeyExchangeMessage: clientMessage,
                                                     serverHostKey: serverHostKey,
                                                     initialExchangeBytes: &initialExchangeBytes,
                                                     allocator: ByteBufferAllocator(),
                                                     expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        )

        initialExchangeBytes.clear()

        // Ok, the server has sent a signature over the exchange hash. Let's change that signature.
        serverResponse.signature = try assertNoThrowWithValue(serverHostKey.sign(digest: SHA256.hash(data: [1, 2, 3, 4, 5])))

        XCTAssertThrowsError(
            try client.receiveServerKeyExchangePayload(serverKeyExchangeMessage: serverResponse,
                                                       initialExchangeBytes: &initialExchangeBytes,
                                                       allocator: ByteBufferAllocator(),
                                                       expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes)
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidExchangeHashSignature)
        }
    }
}


/// This helper extension persists the old way of initializing config for this file.
extension SSHConnectionRole {
    fileprivate static func server(_ hostKeys: [NIOSSHPrivateKey]) -> SSHConnectionRole {
        return .server(SSHServerConfiguration(hostKeys: hostKeys, userAuthDelegate: DenyAllServerAuthDelegate()))
    }

    fileprivate static let client = SSHConnectionRole.client(SSHClientConfiguration(userAuthDelegate: ExplodingAuthDelegate()))
}
