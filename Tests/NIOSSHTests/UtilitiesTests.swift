//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
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

final class UtilitiesTests: XCTestCase {
    func testInsecureEncryptionAlgorithm() {
        let message = ByteBuffer([0, 42, 1, 17, 17, 1, 42, 0, 77, 33, 178, 75, 165, 60, 168, 69, 203, 63, 34, 230, 38, 242, 58, 21, 17, 0, 1, 77, 31, 8, 11, 7])
        let key = SymmetricKey(size: .bits128).withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        let ciphertext = InsecureEncryptionAlgorithm.encrypt(key: key, plaintext: message)
        let plaintext = InsecureEncryptionAlgorithm.decrypt(key: key, ciphertext: ciphertext)
        XCTAssertEqual(message, plaintext)
    }

    func testTestTransportProtection() throws {
        let inboundEncryptionKey = SymmetricKey(size: .bits128)
        let outboundEncryptionKey = SymmetricKey(size: .bits128)
        let inboundMACKey = SymmetricKey(size: .bits128)
        let outboundMACKey = SymmetricKey(size: .bits128)
        let client = TestTransportProtection(initialKeys: .init(
            initialInboundIV: [],
            initialOutboundIV: [],
            inboundEncryptionKey: inboundEncryptionKey,
            outboundEncryptionKey: outboundEncryptionKey,
            inboundMACKey: inboundMACKey,
            outboundMACKey: outboundMACKey
        ))
        let server = TestTransportProtection(initialKeys: .init(
            initialInboundIV: [],
            initialOutboundIV: [],
            inboundEncryptionKey: outboundEncryptionKey,
            outboundEncryptionKey: inboundEncryptionKey,
            inboundMACKey: outboundMACKey,
            outboundMACKey: inboundMACKey
        ))
        let message = SSHMessage.channelRequest(.init(recipientChannel: 1, type: .exec("uname"), wantReply: false))
        let allocator = ByteBufferAllocator()
        var buffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try client.encryptPacket(.init(message: message), to: &buffer))
        XCTAssertNoThrow(try server.decryptFirstBlock(&buffer))
        var decoded = try server.decryptAndVerifyRemainingPacket(&buffer)
        XCTAssertEqual(message, try decoded.readSSHMessage())
    }
}
