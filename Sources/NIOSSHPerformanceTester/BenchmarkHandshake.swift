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
import Crypto
import NIOCore
import NIOSSH

final class BenchmarkHandshake: Benchmark {
    let serverRole = SSHConnectionRole.server(.init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: ExpectPasswordDelegate("password")))
    let clientRole = SSHConnectionRole.client(.init(userAuthDelegate: RepeatingPasswordDelegate("password"), serverAuthDelegate: ClientAlwaysAcceptHostKeyDelegate()))
    let loopCount: Int

    init(loopCount: Int) {
        self.loopCount = loopCount
    }

    func setUp() throws {}

    func tearDown() {}

    func run() throws -> Int {
        for _ in 0 ..< self.loopCount {
            let b2b = BackToBackEmbeddedChannel()
            b2b.client.connect(to: try .init(unixDomainSocketPath: "/foo"), promise: nil)
            b2b.server.connect(to: try .init(unixDomainSocketPath: "/foo"), promise: nil)

            try b2b.client.pipeline.addHandler(NIOSSHHandler(role: self.clientRole, allocator: b2b.client.allocator, inboundChildChannelInitializer: nil)).wait()
            try b2b.server.pipeline.addHandler(NIOSSHHandler(role: self.serverRole, allocator: b2b.server.allocator, inboundChildChannelInitializer: nil)).wait()
            try b2b.interactInMemory()
        }

        return self.loopCount
    }
}
