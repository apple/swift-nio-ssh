//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftNIO project authors
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
import NIOSSH

final class BenchmarkLinearThroughput: Benchmark {
    let serverRole = SSHConnectionRole.server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: ExpectPasswordDelegate("password")))
    let clientRole = SSHConnectionRole.client(.init(userAuthDelegate: RepeatingPasswordDelegate("password"), serverAuthDelegate: ClientAlwaysAcceptHostKeyDelegate()))
    let b2b = BackToBackEmbeddedChannel()
    let messageCount: Int
    let messageSize: Int
    private var message: ByteBuffer?
    private var channel: Channel?

    init(messageCount: Int, messageSize: Int) {
        self.messageCount = messageCount
        self.messageSize = messageSize
    }

    func setUp() throws {
        self.b2b.client.connect(to: try .init(unixDomainSocketPath: "/foo"), promise: nil)
        self.b2b.server.connect(to: try .init(unixDomainSocketPath: "/foo"), promise: nil)

        let clientHandler = NIOSSHHandler(role: self.clientRole, allocator: self.b2b.client.allocator, inboundChildChannelInitializer: nil)

        try self.b2b.client.pipeline.addHandler(clientHandler).wait()
        try self.b2b.server.pipeline.addHandler(NIOSSHHandler(role: self.serverRole, allocator: self.b2b.server.allocator, inboundChildChannelInitializer: nil)).wait()
        try self.b2b.interactInMemory()

        let clientChannelPromise = self.b2b.client.eventLoop.makePromise(of: Channel.self)
        clientHandler.createChannel(clientChannelPromise, channelType: .session) { channel, _ in channel.eventLoop.makeSucceededVoidFuture() }
        try self.b2b.interactInMemory()

        self.channel = try clientChannelPromise.futureResult.wait()
        self.message = ByteBuffer(repeating: 0xFF, count: self.messageSize)
    }

    func tearDown() {}

    func run() throws -> Int {
        let channel = self.channel!
        let message = SSHChannelData(type: .channel, data: .byteBuffer(self.message!))

        for _ in 0 ..< self.messageCount {
            channel.writeAndFlush(message, promise: nil)
            try self.b2b.interactInMemory()
        }

        return self.messageCount
    }
}
