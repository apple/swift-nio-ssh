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
import NIOEmbedded
import XCTest

@testable import NIOSSH

/// Records inbound errors and closes the connection. Used to observe parse errors that
/// `NIOSSHHandler` surfaces via `fireErrorCaught`.
private final class ErrorRecordingHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    private(set) var errors: [Error] = []

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.errors.append(error)
        context.close(promise: nil)
    }
}

class SSHHandlerTests: XCTestCase {
    func testHandlerInitializationOnAdd() throws {
        let allocator = ByteBufferAllocator()
        let channel = EmbeddedChannel()
        let handler = NIOSSHHandler(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            allocator: allocator,
            inboundChildChannelInitializer: nil
        )

        _ = try channel.connect(to: .init(unixDomainSocketPath: "/foo"))

        XCTAssertNoThrow(try channel.pipeline.syncOperations.addHandler(handler))
        XCTAssertEqual(
            try channel.readOutbound(as: IOData.self),
            .byteBuffer(allocator.buffer(string: Constants.version + "\r\n"))
        )
    }

    func testHandlerInitializationActive() throws {
        let allocator = ByteBufferAllocator()
        let channel = EmbeddedChannel()
        let handler = NIOSSHHandler(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            allocator: allocator,
            inboundChildChannelInitializer: nil
        )

        XCTAssertNoThrow(try channel.pipeline.syncOperations.addHandler(handler))
        XCTAssertNil(try channel.readOutbound())

        _ = try channel.connect(to: .init(unixDomainSocketPath: "/foo"))
        XCTAssertEqual(
            try channel.readOutbound(as: IOData.self),
            .byteBuffer(allocator.buffer(string: Constants.version + "\r\n"))
        )
    }

    func testPreAuthBannerReachesParserAcrossReadsAndIsCapped() throws {
        // 32-byte Ed25519 raw host key (same bytes as FuzzResultTests).
        let hostKeyBytes: [UInt8] = [
            132, 233, 148, 139, 128, 175, 236, 108, 87, 48, 49, 251, 46, 42, 132, 84,
            255, 3, 160, 224, 186, 192, 170, 245, 194, 220, 192, 204, 81, 127, 55, 169,
        ]
        let handler = try NIOSSHHandler(
            role: .server(
                .init(
                    hostKeys: [.init(ed25519Key: .init(rawRepresentation: hostKeyBytes))],
                    userAuthDelegate: AcceptEverythingDelegate()
                )
            ),
            allocator: ByteBufferAllocator(),
            inboundChildChannelInitializer: nil
        )
        let recorder = ErrorRecordingHandler()
        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandlers([handler, recorder])
        _ = try channel.connect(to: .init(unixDomainSocketPath: "/fake"))

        // The server is now mid-handshake: it has emitted its own identification string, pre-auth.
        XCTAssertNotNil(try channel.readOutbound(as: IOData.self))

        let initialChunkSize = 128
        let chunkSize = 1024 * 10
        let chunkCount = 100

        var firstChunk = channel.allocator.buffer(capacity: chunkSize)
        firstChunk.writeString("SSH-")
        firstChunk.writeBytes([UInt8](repeating: UInt8(ascii: "A"), count: initialChunkSize - 4))
        XCTAssertNoThrow(try channel.writeInbound(firstChunk))
        XCTAssertTrue(channel.isActive)
        XCTAssertTrue(recorder.errors.isEmpty)

        // Keep feeding data until we hit an error without ever adding '\n'.
        var next = channel.allocator.buffer(capacity: chunkSize)
        next.writeBytes([UInt8](repeating: UInt8(ascii: "A"), count: chunkSize))
        for _ in 1..<chunkCount {
            XCTAssertNoThrow(try channel.writeInbound(next))
            if recorder.errors.count > 0 {
                break
            }
        }
        // Check that an error was propagated and the channel is no longer active.
        XCTAssertFalse(recorder.errors.isEmpty)
        XCTAssertFalse(channel.isActive)
    }
}
