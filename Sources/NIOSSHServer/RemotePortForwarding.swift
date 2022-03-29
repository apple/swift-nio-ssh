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

import Dispatch
import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix
import NIOSSH

// Remote port forwarding is a fun feature of SSH where a client can ask an SSH server to listen on a local
// port on its behalf. This file provides a some examples of how to configure this.
// Please note that, as with the rest of this example, there are important security features missing from
// this demo.
final class RemotePortForwarder {
    private var serverChannel: Channel?

    private var inboundSSHHandler: NIOSSHHandler

    init(inboundSSHHandler: NIOSSHHandler) {
        self.inboundSSHHandler = inboundSSHHandler
    }

    func beginListening(on host: String, port: Int, loop: EventLoop) -> EventLoopFuture<Int?> {
        ServerBootstrap(group: loop).serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SocketOptionName(SO_REUSEADDR)), value: 1)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SocketOptionName(SO_REUSEADDR)), value: 1)
            .childChannelInitializer { childChannel in
                let (ours, theirs) = GlueHandler.matchedPair()

                // Ok, ask for the remote channel to be created. This needs remote half closure turned on and to be
                // set up for data I/O.
                let promise = loop.makePromise(of: Channel.self)
                self.inboundSSHHandler.createChannel(promise, channelType: .forwardedTCPIP(.init(listeningHost: host, listeningPort: childChannel.localAddress!.port!, originatorAddress: childChannel.remoteAddress!))) { sshChildChannel, _ in
                    sshChildChannel.pipeline.addHandlers([DataToBufferCodec(), theirs]).flatMap {
                        sshChildChannel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                    }
                }

                // Great, now we add the glue handler to the newly-accepted channel, and then we don't allow this channel to go
                // active until the SSH channel has. Both should go active at once.
                return childChannel.pipeline.addHandler(ours).flatMap { _ in promise.futureResult }.map { _ in () }
            }
            .bind(host: host, port: port).map { channel in
                if port == 0 {
                    return channel.localAddress!.port!
                } else {
                    return nil
                }
            }
    }

    func stopListening() {
        self.serverChannel?.close(promise: nil)
    }
}

final class RemotePortForwarderGlobalRequestDelegate: GlobalRequestDelegate {
    // This example delegate only tolerates one bound port per connection, but this is an artificial limit.
    private var forwarder: RemotePortForwarder?

    func tcpForwardingRequest(_ request: GlobalRequest.TCPForwardingRequest, handler: NIOSSHHandler, promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>) {
        switch request {
        case .listen(host: let host, port: let port):
            guard self.forwarder == nil else {
                promise.fail(SSHServerError.alreadyListening)
                return
            }

            let forwarder = RemotePortForwarder(inboundSSHHandler: handler)
            forwarder.beginListening(on: host, port: port, loop: promise.futureResult.eventLoop).map {
                GlobalRequest.TCPForwardingResponse(boundPort: $0)
            }.cascade(to: promise)
        case .cancel:
            guard let forwarder = self.forwarder else {
                promise.fail(SSHServerError.notListening)
                return
            }

            self.forwarder = nil
            forwarder.stopListening()
        }
    }

    deinit {
        self.forwarder?.stopListening()
    }
}
