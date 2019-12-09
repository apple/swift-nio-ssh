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

import CryptoKit
import NIO
@testable import NIOSSH
import XCTest


final class SSHEncryptedTrafficTests: XCTestCase {
    private var serializer: SSHPacketSerializer!
    private var parser: SSHPacketParser!

    private var buffer = ByteBufferAllocator().buffer(capacity: 1024)

    override func setUp() {
        self.serializer = SSHPacketSerializer()
        self.parser = SSHPacketParser(allocator: .init())

        self.assertPacketRoundTrips(.version("SSH-2.0-SwiftSSH_1.0"))
    }

    override func tearDown() {
        self.serializer = nil
        self.parser = nil
    }

    private func assertPacketRoundTrips(_ message: SSHMessage, file: StaticString = #file, line: UInt = #line) {
        self.buffer.clear()
        XCTAssertNoThrow(try self.serializer.serialize(message: message, to: &self.buffer), file: file, line: line)
        self.parser.append(bytes: &self.buffer)

        var packet: SSHMessage? = nil
        XCTAssertNoThrow(packet = try self.parser.nextPacket())
        XCTAssertEqual(packet, message)
        XCTAssertNil(try self.parser.nextPacket())
    }

    private func assertPacketErrors(_ message: SSHMessage, file: StaticString = #file, line: UInt = #line) {
        self.buffer.clear()
        XCTAssertNoThrow(try self.serializer.serialize(message: .serviceRequest(.init(service: ByteBuffer.of(string: "some service"))), to: &self.buffer))
        self.parser.append(bytes: &self.buffer)

        XCTAssertThrowsError(try self.parser.nextPacket()) { error in
            print(error)
        }
    }

    private func protect(_ protection: Protection) {
        let (clientProtection, serverProtection) = protection.protections()
        self.serializer.addEncryption(clientProtection)
        self.parser.addEncryption(serverProtection)
    }

    func testBasicEncryptedPacketExchange() {
        self.protect(.aes128)
        self.assertPacketRoundTrips(.serviceRequest(.init(service: ByteBuffer.of(string: "some service"))))
        self.assertPacketRoundTrips(.serviceAccept(.init(service: ByteBuffer.of(string: "some service"))))
    }

    func testBasicExchangeAES256() {
        self.protect(.aes256)
        self.assertPacketRoundTrips(.serviceRequest(.init(service: ByteBuffer.of(string: "some service"))))
        self.assertPacketRoundTrips(.serviceAccept(.init(service: ByteBuffer.of(string: "some service"))))
    }

    func testRejectsCorruptedPacket() {
        self.protect(.aes128)
        self.buffer.clear()
        XCTAssertNoThrow(try self.serializer.serialize(message: .serviceRequest(.init(service: ByteBuffer.of(string: "some service"))), to: &self.buffer))

        // Mutate the buffer. We don't allow mutating the length because if we set the length to very long the parser returns nil instead.
        let index = (4..<self.buffer.writerIndex).randomElement()!
        let currentValue = self.buffer.getInteger(at: index, as: UInt8.self)!
        self.buffer.setInteger(currentValue ^ 0xff, at: index)  // Flip every bit
        self.parser.append(bytes: &self.buffer)

        XCTAssertThrowsError(try self.parser.nextPacket()) { error in
            print(error)
        }
    }

    func testRejectsIncompatibleKeys() {
        let (clientProtection, _) = Protection.aes128.protections()
        let (_, serverProtection) = Protection.aes128.protections()
        self.serializer.addEncryption(clientProtection)
        self.parser.addEncryption(serverProtection)


    }
}


extension SSHEncryptedTrafficTests {
    fileprivate enum Protection {
        case aes128
        case aes256

        fileprivate func protections() -> (client: NIOSSHTransportProtection, server: NIOSSHTransportProtection) {
            switch self {
            case .aes128:
                let protection = self.aes128Protection()
                return (client: protection.client, server: protection.server)
            case .aes256:
                let protection = self.aes256Protection()
                return (client: protection.client, server: protection.server)
            }
        }

        private func aes128Protection() -> (client: AES128GCMOpenSSHTransportProtection, server: AES128GCMOpenSSHTransportProtection) {
            let keys = self.generateKeys(keySize: .bits128, ivSize: 12, macSize: .bits128)
            let client = try! AES128GCMOpenSSHTransportProtection(initialKeys: keys)
            let server = try! AES128GCMOpenSSHTransportProtection(initialKeys: keys.inverted)
            return (client: client, server: server)
        }

        private func aes256Protection() -> (client: AES256GCMOpenSSHTransportProtection, server: AES256GCMOpenSSHTransportProtection) {
            let keys = self.generateKeys(keySize: .bits256, ivSize: 12, macSize: .bits128)
            let client = try! AES256GCMOpenSSHTransportProtection(initialKeys: keys)
            let server = try! AES256GCMOpenSSHTransportProtection(initialKeys: keys.inverted)
            return (client: client, server: server)
        }

        private func generateKeys(keySize: SymmetricKeySize, ivSize: Int, macSize: SymmetricKeySize) -> NIOSSHSessionKeys {
            return NIOSSHSessionKeys(initialInboundIV: .init(randomBytes: ivSize),
                                     initialOutboundIV: .init(randomBytes: ivSize),
                                     inboundEncryptionKey: SymmetricKey(size: keySize),
                                     outboundEncryptionKey: SymmetricKey(size: keySize),
                                     inboundMACKey: SymmetricKey(size: macSize),
                                     outboundMACKey: SymmetricKey(size: macSize))
        }
    }
}

