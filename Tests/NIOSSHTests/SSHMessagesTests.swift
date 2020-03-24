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

final class SSHMessagesTests: XCTestCase {
    func testDisconnnect() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.disconnect(.init(reason: 2, description: "user closed connection", tag: ByteBuffer.of(bytes: [0])))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.DisconnectMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testIgnore() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        var otherBuffer = ByteBufferAllocator().buffer(capacity: 100)
        otherBuffer.writeString("A string!")
        let message = SSHMessage.ignore(.init(data: otherBuffer))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.IgnoreMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testUnimplemented() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.unimplemented(.init(sequenceNumber: 77))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.UnimplementedMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testServiceRequest() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.serviceRequest(.init(service: "ssh-userauth"))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ServiceRequestMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testServiceAccept() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.serviceAccept(.init(service: "ssh-userauth"))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ServiceAcceptMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testKeyExchangeMessage() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.keyExchange(.init(
            cookie: ByteBuffer.of(bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]),
            keyExchangeAlgorithms: [Substring("keyExchange1"), Substring("keyExchange2")],
            serverHostKeyAlgorithms: [Substring("serverHostKeyAlgorithms1"), Substring("serverHostKeyAlgorithms2")],
            encryptionAlgorithmsClientToServer: [Substring("encryptionAlgorithmsClientToServer1"), Substring("encryptionAlgorithmsClientToServer2")],
            encryptionAlgorithmsServerToClient: [Substring("encryptionAlgorithmsServerToClient1"), Substring("encryptionAlgorithmsServerToClient2")],
            macAlgorithmsClientToServer: [Substring("macAlgorithmsClientToServer1"), Substring("macAlgorithmsClientToServer2")],
            macAlgorithmsServerToClient: [Substring("macAlgorithmsServerToClient1"), Substring("macAlgorithmsServerToClient2")],
            compressionAlgorithmsClientToServer: [Substring("compressionAlgorithmsClientToServer1"), Substring("compressionAlgorithmsClientToServer2")],
            compressionAlgorithmsServerToClient: [Substring("compressionAlgorithmsServerToClient1"), Substring("compressionAlgorithmsServerToClient2")],
            languagesClientToServer: [Substring("languagesClientToServer1"), Substring("languagesClientToServer2")],
            languagesServerToClient: [Substring("languagesServerToClient1"), Substring("languagesServerToClient2")],
            firstKexPacketFollows: false))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.KeyExchangeMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testKeyExchangeInit() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.keyExchangeInit(.init(publicKey: ByteBuffer.of(bytes: [42])))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.KeyExchangeECDHInitMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testKeyExchangeReply() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let key = NIOSSHHostPrivateKey(ed25519Key: .init())
        var digest = SHA256()
        digest.update(data: [24])
        let signature = try key.sign(digest: digest.finalize())
        let message = SSHMessage.keyExchangeReply(.init(hostKey: key.publicKey, publicKey: ByteBuffer.of(bytes: [42]), signature: signature))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.KeyExchangeECDHReplyMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testNewKeys() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.newKeys

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
    }

    func testUserAuthRequest() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.userAuthRequest(.init(username: "test", service: "ssh-connection", method: .password("pwd")))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.UserAuthRequestMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testUserAuthFailure() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.userAuthFailure(.init(authentications: [Substring("password")], partialSuccess: false))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.UserAuthFailureMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testUserAuthSuccess() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.userAuthSuccess

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
    }

    func testGlobalRequest() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.globalRequest(.init(name: "test", wantReply: false))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.GlobalRequestMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelOpen() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelOpen(.init(type: .session, senderChannel: 0, initialWindowSize: 42, maximumPacketSize: 24))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelOpenMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelOpenConfirmation() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelOpenConfirmation(.init(recipientChannel: 0, senderChannel: 1, initialWindowSize: 42, maximumPacketSize: 24))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelOpenConfirmationMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelOpenFailure() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelOpenFailure(.init(recipientChannel: 0, reasonCode: 1, description: "desc", language: "lang"))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelOpenFailureMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelWindowAdjust() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelWindowAdjust(.init(recipientChannel: 0, bytesToAdd: 42))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelWindowAdjustMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelData() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelData(.init(recipientChannel: 0, data: ByteBuffer.of(string: "hello")))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelDataMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelExtendedData() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelExtendedData(.init(recipientChannel: 0, dataTypeCode: .stderr, data: ByteBuffer.of(string: "hello")))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelExtendedDataMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelEOF() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelEOF(.init(recipientChannel: 0))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelEOFMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelClose() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelClose(.init(recipientChannel: 0))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelCloseMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelRequest() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        var message = SSHMessage.channelRequest(.init(recipientChannel: 0, type: .env("A", "B"), wantReply: true))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        message = SSHMessage.channelRequest(.init(recipientChannel: 0, type: .exec("date"), wantReply: true))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        message = SSHMessage.channelRequest(.init(recipientChannel: 0, type: .exit(1), wantReply: true))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelRequestMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelSuccess() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelSuccess(.init(recipientChannel: 0))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelSuccessMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testChannelFailure() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.channelFailure(.init(recipientChannel: 0))

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.writeBytes([SSHMessage.ChannelFailureMessage.id, 0, 0])
        XCTAssertNil(try buffer.readSSHMessage())
    }

    func testTypeError() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)

        XCTAssertNil(try buffer.readSSHMessage())

        buffer.writeBytes([127])
        XCTAssertThrowsError(try buffer.readSSHMessage())
    }

    func testRequestSuccess() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        var bucketOBytes = ByteBufferAllocator().buffer(capacity: 24)
        bucketOBytes.writeBytes(0..<24)

        let message = SSHMessage.requestSuccess(.init(bytes: bucketOBytes))
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.clear()
        buffer.writeBytes([SSHMessage.RequestSuccessMessage.id] + Array(0..<24))
        XCTAssertEqual(try buffer.readSSHMessage(), message)
    }

    func testRequestFailure() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        let message = SSHMessage.requestFailure

        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)

        buffer.clear()
        buffer.writeBytes([SSHMessage.RequestFailureMessage.id])
        XCTAssertEqual(try buffer.readSSHMessage(), message)
    }
}
