//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019-2024 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOEmbedded
import NIOSSH

func runManySmallCommandsPerConnection(numberOfWrites: Int) throws {
    final class ServerHandler: ChannelInboundHandler {
        typealias InboundIn = SSHChannelData
        typealias OutboundOut = SSHChannelData

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            context.write(data, promise: nil)
        }

        func channelReadComplete(context: ChannelHandlerContext) {
            context.flush()
        }
    }

    final class ClientHandler: ChannelInboundHandler {
        typealias InboundIn = SSHChannelData
        typealias OutboundOut = SSHChannelData

        private var didSend: Bool = false
        private let message: ByteBuffer = ByteBuffer(string: "hello")
        var readBytes: Int = 0

        func handlerAdded(context: ChannelHandlerContext) {
            if context.channel.isActive {
                self.sendInitialMessage(context: context)
            }
        }

        func channelActive(context: ChannelHandlerContext) {
            self.sendInitialMessage(context: context)
        }

        private func sendInitialMessage(context: ChannelHandlerContext) {
            if self.didSend { return }

            self.didSend = true
            let data = SSHChannelData(type: .channel, data: .byteBuffer(message))
            context.writeAndFlush(self.wrapOutboundOut(data), promise: nil)
        }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            let data = self.unwrapInboundIn(data)
            guard case .byteBuffer(let buffer) = data.data else {
                fatalError()
            }
            self.readBytes += buffer.readableBytes

            if self.readBytes == self.message.readableBytes {
                context.close(promise: nil)
            }
        }
    }

    let loop = EmbeddedEventLoop()
    let hostKey = NIOSSHPrivateKey(ed25519Key: .init())

    let clientChannel = EmbeddedChannel(loop: loop)
    let serverChannel = EmbeddedChannel(loop: loop)

    try clientChannel.pipeline.addHandler(
        NIOSSHHandler(
            role: .client(
                .init(
                    userAuthDelegate: HardcodedClientPasswordDelegate(),
                    serverAuthDelegate: AcceptAllHostKeysDelegate()
                )
            ),
            allocator: clientChannel.allocator,
            inboundChildChannelInitializer: nil
        )
    ).wait()
    try serverChannel.pipeline.addHandler(
        NIOSSHHandler(
            role: .server(
                .init(
                    hostKeys: [hostKey],
                    userAuthDelegate: HardcodedServerPasswordDelegate()
                )
            ),
            allocator: serverChannel.allocator,
            inboundChildChannelInitializer: { channel, _ in
                channel.pipeline.addHandler(ServerHandler())
            }
        )
    ).wait()

    try clientChannel.connect(to: SocketAddress(ipAddress: "1.2.3.4", port: 5678)).wait()
    try serverChannel.connect(to: SocketAddress(ipAddress: "1.2.3.4", port: 5678)).wait()

    for _ in 0..<numberOfWrites {
        let clientHandler = ClientHandler()

        let childChannelFuture: EventLoopFuture<Channel> = clientChannel.pipeline.handler(type: NIOSSHHandler.self)
            .flatMap { sshHandler in
                let promise = clientChannel.eventLoop.makePromise(of: Channel.self)
                sshHandler.createChannel(promise) { childChannel, _ in
                    childChannel.pipeline.addHandlers([clientHandler])
                }
                return promise.futureResult
            }
        clientChannel.embeddedEventLoop.run()
        try interactInMemory(clientChannel, serverChannel)

        let childChannel = try childChannelFuture.wait()

        try childChannel.closeFuture.wait()
    }

    try clientChannel.close().wait()
    try serverChannel.close().wait()

}
