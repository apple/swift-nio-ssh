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

import NIO
import NIOSSH

// This file contains an example NIO SSH client. As NIO SSH is currently under active
// development this file doesn't currently do all that much, but it does provide a binary you
// can kick off to get a feel for how NIO SSH drives the connection live. As the feature set of
// NIO SSH increases we'll be adding to this client to try to make it a better example of what you
// can do with NIO SSH.
final class ErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Error in pipeline: \(error)")
        context.close(promise: nil)
    }
}

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
defer {
    try! group.syncShutdownGracefully()
}

let bootstrap = ClientBootstrap(group: group)
    .channelInitializer { channel in
        channel.pipeline.addHandlers([NIOSSHHandler(role: .client, allocator: channel.allocator), ErrorHandler()])
    }
    .channelOption(ChannelOptions.socket(SOL_SOCKET, SO_REUSEADDR), value: 1)
    .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)

// First argument is the program path
let arguments = CommandLine.arguments
let arg1 = arguments.dropFirst().first
let arg2 = arguments.dropFirst().dropFirst().first

enum ConnectTo {
    case ip(host: String, port: Int)
    case unixDomainSocket(path: String)
}

let defaultHost = "::1"
let defaultPort: Int = 8888
let connectTarget: ConnectTo

switch (arg1, arg1.flatMap { Int($0) }, arg2, arg2.flatMap { Int($0) }) {
case (.some(let h), _ , _, .some(let p)):
    /* second arg an integer --> host port */
    connectTarget = .ip(host: h, port: p)
case (_, .some(let p), .none, .none):
    /* first arg an integer --> port */
    connectTarget = .ip(host: defaultHost, port: p)
case (.some(let portString), .none, .none, .none):
    /* couldn't parse as number --> uds-path */
    connectTarget = .unixDomainSocket(path: portString)
default:
    connectTarget = ConnectTo.ip(host: defaultHost, port: defaultPort)
}

let channel = try { () -> Channel in
    switch connectTarget {
    case .ip(let host, let port):
        return try bootstrap.connect(host: host, port: port).wait()
    case .unixDomainSocket(let path):
        return try bootstrap.connect(unixDomainSocketPath: path).wait()
    }
    }()

print("Client started and connected to \(channel.remoteAddress!)")

// Wait for the connection to close
try channel.closeFuture.wait()

print("Client closed")
