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
@testable import NIOSSH
import XCTest

class SSHHandlerTests: XCTestCase {
    func testHandlerInitializationOnAdd() throws {
        let allocator = ByteBufferAllocator()
        let channel = EmbeddedChannel()
        let handler = NIOSSHHandler(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())), allocator: allocator, inboundChildChannelInitializer: nil)

        _ = try channel.connect(to: .init(unixDomainSocketPath: "/foo"))

        XCTAssertNoThrow(try channel.pipeline.addHandler(handler).wait())
        XCTAssertEqual(try channel.readOutbound(as: IOData.self), .byteBuffer(allocator.buffer(string: Constants.version + "\r\n")))
    }

    func testHandlerInitializationActive() throws {
        let allocator = ByteBufferAllocator()
        let channel = EmbeddedChannel()
        let handler = NIOSSHHandler(role: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())), allocator: allocator, inboundChildChannelInitializer: nil)

        XCTAssertNoThrow(try channel.pipeline.addHandler(handler).wait())
        XCTAssertNil(try channel.readOutbound())

        _ = try channel.connect(to: .init(unixDomainSocketPath: "/foo"))
        XCTAssertEqual(try channel.readOutbound(as: IOData.self), .byteBuffer(allocator.buffer(string: Constants.version + "\r\n")))
    }
}
