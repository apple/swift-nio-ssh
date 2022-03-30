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
import NIOCore
import NIOPosix
import NIOSSH

final class PortForwardingServer {
    private var serverChannel: Channel?
    private let serverLoop: EventLoop
    private let group: EventLoopGroup
    private let bindHost: Substring
    private let bindPort: Int
    private let forwardingChannelConstructor: (Channel) -> EventLoopFuture<Void>

    init(group: EventLoopGroup,
         bindHost: Substring,
         bindPort: Int,
         _ forwardingChannelConstructor: @escaping (Channel) -> EventLoopFuture<Void>) {
        self.serverLoop = group.next()
        self.group = group
        self.forwardingChannelConstructor = forwardingChannelConstructor
        self.bindHost = bindHost
        self.bindPort = bindPort
    }

    func run() -> EventLoopFuture<Void> {
        ServerBootstrap(group: self.serverLoop, childGroup: self.group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer(self.forwardingChannelConstructor)
            .bind(host: String(self.bindHost), port: self.bindPort)
            .flatMap {
                self.serverChannel = $0
                return $0.closeFuture
            }
    }

    func close() -> EventLoopFuture<Void> {
        self.serverLoop.flatSubmit {
            guard let server = self.serverChannel else {
                // The server wasn't created yet, so we can just shut down straight away and let
                // the OS clean us up.
                return self.serverLoop.makeSucceededFuture(())
            }

            return server.close()
        }
    }
}

/// A simple handler that wraps data into SSHChannelData for forwarding.
final class SSHWrapperHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .channel = data.type, case .byteBuffer(let buffer) = data.data else {
            context.fireErrorCaught(SSHClientError.invalidData)
            return
        }

        context.fireChannelRead(self.wrapInboundOut(buffer))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        let wrapped = SSHChannelData(type: .channel, data: .byteBuffer(data))
        context.write(self.wrapOutboundOut(wrapped), promise: promise)
    }
}
