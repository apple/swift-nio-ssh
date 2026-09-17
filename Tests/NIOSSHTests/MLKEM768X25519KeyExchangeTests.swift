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
import XCTest

@testable import NIOSSH

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
final class MLKEM768X25519KeyExchangeTests: XCTestCase {
    private func keyExchangeAgreed(_ first: KeyExchangeResult, _ second: KeyExchangeResult) {
        XCTAssertEqual(first.sessionID, second.sessionID)
        XCTAssertEqual(first.keys.initialInboundIV, second.keys.initialOutboundIV)
        XCTAssertEqual(first.keys.initialOutboundIV, second.keys.initialInboundIV)
        XCTAssertEqual(first.keys.inboundEncryptionKey, second.keys.outboundEncryptionKey)
        XCTAssertEqual(first.keys.outboundEncryptionKey, second.keys.inboundEncryptionKey)
        XCTAssertEqual(first.keys.inboundMACKey, second.keys.outboundMACKey)
        XCTAssertEqual(first.keys.outboundMACKey, second.keys.inboundMACKey)
    }

    func testRoundTripProducesMatchingKeys() throws {
        var server = MLKEM768X25519KeyExchange(
            ourRole: .mlkemTest_server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = MLKEM768X25519KeyExchange(ourRole: .mlkemTest_client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 4096)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())

        // Per OpenSSH 9.9 wire format: client init payload is MLKEM768 public
        // key (1184 B) || X25519 public key (32 B).
        XCTAssertEqual(
            clientMessage.publicKey.readableBytes,
            MLKEM768X25519KeyExchange.mlkemPublicKeySize + MLKEM768X25519KeyExchange.x25519PublicKeySize
        )

        let (serverKeys, serverResponse) = try server.completeKeyExchangeServerSide(
            clientKeyExchangeMessage: clientMessage,
            serverHostKey: serverHostKey,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
        )

        // Server reply payload is MLKEM768 ciphertext (1088 B) || X25519
        // public key (32 B).
        XCTAssertEqual(
            serverResponse.publicKey.readableBytes,
            MLKEM768X25519KeyExchange.mlkemCiphertextSize + MLKEM768X25519KeyExchange.x25519PublicKeySize
        )

        initialExchangeBytes.clear()

        let clientKeys = try client.receiveServerKeyExchangePayload(
            serverKeyExchangeMessage: serverResponse,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
        )

        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testReusesPreviousSessionIdentifier() throws {
        var previousSessionIdentifier = ByteBufferAllocator().buffer(capacity: 32)
        previousSessionIdentifier.writeBytes(0..<32)

        var server = MLKEM768X25519KeyExchange(
            ourRole: .mlkemTest_server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: previousSessionIdentifier
        )
        var client = MLKEM768X25519KeyExchange(
            ourRole: .mlkemTest_client,
            previousSessionIdentifier: previousSessionIdentifier
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 4096)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try server.completeKeyExchangeServerSide(
            clientKeyExchangeMessage: clientMessage,
            serverHostKey: serverHostKey,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
        )

        initialExchangeBytes.clear()

        let clientKeys = try client.receiveServerKeyExchangePayload(
            serverKeyExchangeMessage: serverResponse,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
        )

        self.keyExchangeAgreed(serverKeys, clientKeys)
        XCTAssertEqual(serverKeys.sessionID, previousSessionIdentifier)
    }

    func testRejectsTruncatedClientInit() throws {
        var server = MLKEM768X25519KeyExchange(
            ourRole: .mlkemTest_server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())
        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 4096)

        var shortPayload = ByteBufferAllocator().buffer(capacity: 100)
        shortPayload.writeBytes(repeatElement(UInt8(0), count: 100))
        let badMessage = SSHMessage.KeyExchangeECDHInitMessage(publicKey: shortPayload)

        XCTAssertThrowsError(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: badMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )
    }

    func testAlgorithmName() {
        XCTAssertEqual(MLKEM768X25519KeyExchange.keyExchangeAlgorithmNames, ["mlkem768x25519-sha256"])
    }
}

/// Mirrors the helper in `ECKeyExchangeTests.swift` — kept fileprivate
/// so it doesn't collide with that file's `extension SSHConnectionRole`.
extension SSHConnectionRole {
    fileprivate static func mlkemTest_server(_ hostKeys: [NIOSSHPrivateKey]) -> SSHConnectionRole {
        .server(SSHServerConfiguration(hostKeys: hostKeys, userAuthDelegate: DenyAllServerAuthDelegate()))
    }

    fileprivate static var mlkemTest_client: SSHConnectionRole {
        .client(
            SSHClientConfiguration(
                userAuthDelegate: ExplodingAuthDelegate(),
                serverAuthDelegate: AcceptAllHostKeysDelegate()
            )
        )
    }
}
