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
import Foundation
import NIOCore
import NIOEmbedded
import NIOFoundationCompat
import NIOSSH
import XCTest

final class AcceptEverythingDelegate: NIOSSHServerUserAuthenticationDelegate {
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
        .password
    }

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        responsePromise.succeed(.success)
    }
}

final class FuzzResultTests: XCTestCase {
    var channel: EmbeddedChannel!

    static let hostKeyBytes: [UInt8] = [
        132, 233, 148, 139, 128, 175, 236, 108, 87, 48, 49, 251, 46, 42, 132, 84,
        255, 3, 160, 224, 186, 192, 170, 245, 194, 220, 192, 204, 81, 127, 55, 169,
    ]

    override func setUp() {
        let handler = try! NIOSSHHandler(role: .server(.init(hostKeys: [.init(ed25519Key: .init(rawRepresentation: Self.hostKeyBytes))], userAuthDelegate: AcceptEverythingDelegate())), allocator: ByteBufferAllocator(), inboundChildChannelInitializer: nil)
        self.channel = EmbeddedChannel(handler: handler)
        self.channel.connect(to: try! SocketAddress(unixDomainSocketPath: "/fake"), promise: nil)
    }

    override func tearDown() {
        try? self.channel.eventLoop.syncShutdownGracefully()
        self.channel = nil
    }

    private func runTest(base64EncodedTestData testBytes: String) {
        var buffer = self.channel.allocator.buffer(capacity: testBytes.utf8.count) // Too big, but ok.
        buffer.writeContiguousBytes(Data(base64Encoded: testBytes)!)

        // This test must only not crash.
        _ = try? self.channel.writeInbound(buffer)
    }

    func testOne() {
        self.runTest(base64EncodedTestData: "AAoKDQ==")
    }

    func testTwo() {
        self.runTest(base64EncodedTestData: "U1NILTIuMAAAsA0KAAAADQtR+ABpY3VkdDY1ACA=")
    }
}
