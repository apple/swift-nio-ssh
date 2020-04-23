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
import NIOSSH
import XCTest

enum EndToEndTestError: Error {
    case unableToCreateChildChannel
}

class BackToBackEmbeddedChannel {
    private(set) var client: EmbeddedChannel
    private(set) var server: EmbeddedChannel
    private var loop: EmbeddedEventLoop

    private(set) var activeServerChannels: [Channel]

    var clientSSHHandler: NIOSSHHandler? {
        try? self.client.pipeline.handler(type: NIOSSHHandler.self).wait()
    }

    var serverSSHHandler: NIOSSHHandler? {
        try? self.client.pipeline.handler(type: NIOSSHHandler.self).wait()
    }

    init() {
        self.loop = EmbeddedEventLoop()
        self.client = EmbeddedChannel(loop: self.loop)
        self.server = EmbeddedChannel(loop: self.loop)
        self.activeServerChannels = []
    }

    func run() {
        self.loop.run()
    }

    func interactInMemory() throws {
        var workToDo = true

        while workToDo {
            workToDo = false

            self.loop.run()
            let clientDatum = try self.client.readOutbound(as: IOData.self)
            let serverDatum = try self.server.readOutbound(as: IOData.self)

            if let clientMsg = clientDatum {
                try self.server.writeInbound(clientMsg)
                workToDo = true
            }

            if let serverMsg = serverDatum {
                try self.client.writeInbound(serverMsg)
                workToDo = true
            }
        }
    }

    func activate() throws {
        // A weird wrinkle of embedded channel is that it only properly activates on connect.
        try self.client.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
        try self.server.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
    }

    func configureWithHarness(_ harness: TestHarness) throws {
        let clientHandler = NIOSSHHandler(role: .client(.init(userAuthDelegate: harness.clientAuthDelegate, globalRequestDelegate: harness.clientGlobalRequestDelegate)),
                                          allocator: self.client.allocator,
                                          inboundChildChannelInitializer: nil)
        let serverHandler = NIOSSHHandler(role: .server(.init(hostKeys: harness.serverHostKeys, userAuthDelegate: harness.serverAuthDelegate, globalRequestDelegate: harness.serverGlobalRequestDelegate)),
                                          allocator: self.server.allocator) { channel, _ in
            self.activeServerChannels.append(channel)
            channel.closeFuture.whenComplete { _ in self.activeServerChannels.removeAll(where: { $0 === channel }) }
            return channel.eventLoop.makeSucceededFuture(())
        }

        try self.client.pipeline.addHandler(clientHandler).wait()
        try self.server.pipeline.addHandler(serverHandler).wait()
    }

    func finish() throws {
        XCTAssertNoThrow(XCTAssertTrue(try self.client.finish(acceptAlreadyClosed: true).isClean))
        XCTAssertNoThrow(XCTAssertTrue(try self.server.finish(acceptAlreadyClosed: true).isClean))
        XCTAssertNoThrow(try self.loop.syncShutdownGracefully())
    }

    func createNewChannel() throws -> Channel {
        var clientChannel = Optional<Channel>.none
        self.clientSSHHandler?.createChannel { channel, _ in
            clientChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = clientChannel else {
            XCTFail("Unable to create child channel")
            throw EndToEndTestError.unableToCreateChildChannel
        }

        return channel
    }
}

/// A straightforward test harness.
struct TestHarness {
    var clientAuthDelegate: NIOSSHClientUserAuthenticationDelegate = InfinitePasswordDelegate()

    var clientGlobalRequestDelegate: GlobalRequestDelegate?

    var serverAuthDelegate: NIOSSHServerUserAuthenticationDelegate = DenyThenAcceptDelegate(messagesToDeny: 0)

    var serverGlobalRequestDelegate: GlobalRequestDelegate?

    var serverHostKeys: [NIOSSHPrivateKey] = [.init(ed25519Key: .init())]
}

final class UserEventExpecter: ChannelInboundHandler {
    typealias InboundIn = Any

    var userEvents: [Any] = []

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        self.userEvents.append(event)
        context.fireUserInboundEventTriggered(event)
    }
}

class EndToEndTests: XCTestCase {
    var channel: BackToBackEmbeddedChannel!

    override func setUp() {
        self.channel = BackToBackEmbeddedChannel()
    }

    override func tearDown() {
        try? self.channel.finish()
        self.channel = nil
    }

    /// This test validates that all the channel requests round-trip appropriately.
    func testChannelRequests() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel.
        let clientChannel = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        guard let serverChannel = self.channel.activeServerChannels.first else {
            XCTFail("Server channel not created")
            return
        }

        let userEventRecorder = UserEventExpecter()
        XCTAssertNoThrow(try serverChannel.pipeline.addHandler(userEventRecorder).wait())

        func helper<Event: Equatable>(_ event: Event) {
            var clientSent = false
            clientChannel.triggerUserOutboundEvent(event).whenSuccess { clientSent = true }
            XCTAssertNoThrow(try self.channel.interactInMemory())

            XCTAssertTrue(clientSent)
            XCTAssertEqual(userEventRecorder.userEvents.last as? Event?, event)
        }

        helper(SSHChannelRequestEvent.ExecRequest(command: "uname -a", wantReply: true))
        helper(SSHChannelRequestEvent.EnvironmentRequest(wantReply: true, name: "foo", value: "bar"))
        helper(SSHChannelRequestEvent.ExitStatus(exitStatus: 5))
        helper(SSHChannelRequestEvent.PseudoTerminalRequest(wantReply: true,
                                                            term: "vt100",
                                                            terminalCharacterWidth: 80,
                                                            terminalRowHeight: 24,
                                                            terminalPixelWidth: 0,
                                                            terminalPixelHeight: 0,
                                                            terminalModes: .init([.ECHO: 5])))
        helper(SSHChannelRequestEvent.ShellRequest(wantReply: true))
        helper(SSHChannelRequestEvent.ExitSignal(signalName: "ILL", errorMessage: "illegal instruction", language: "en", dumpedCore: true))
        helper(SSHChannelRequestEvent.SubsystemRequest(subsystem: "file transfer", wantReply: false))
        helper(SSHChannelRequestEvent.WindowChangeRequest(terminalCharacterWidth: 0, terminalRowHeight: 0, terminalPixelWidth: 720, terminalPixelHeight: 480))
        helper(SSHChannelRequestEvent.LocalFlowControlRequest(clientCanDo: true))
        helper(SSHChannelRequestEvent.SignalRequest(signal: "USR1"))
        helper(ChannelSuccessEvent())
        helper(ChannelFailureEvent())
    }

    func testGlobalRequestWithDefaultDelegate() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        func helper(_ request: GlobalRequest.TCPForwardingRequest) throws -> GlobalRequest.GlobalRequestResponse {
            let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.GlobalRequestResponse.self)
            self.channel.clientSSHHandler?.sendTCPForwardingRequest(request, promise: promise)
            try self.channel.interactInMemory()
            return try promise.futureResult.wait()
        }

        // The default delegate rejects everything.
        XCTAssertThrowsError(try helper(.listen(host: "localhost", port: 8765))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .globalRequestRefused)
        }
        XCTAssertThrowsError(try helper(.cancel(host: "localhost", port: 8765))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .globalRequestRefused)
        }
    }

    func testGlobalRequestWithCustomDelegate() throws {
        class CustomGlobalRequestDelegate: GlobalRequestDelegate {
            var requests: [GlobalRequest.TCPForwardingRequest] = []

            var port: Int? = 0

            func tcpForwardingRequest(_ request: GlobalRequest.TCPForwardingRequest, handler: NIOSSHHandler, promise: EventLoopPromise<GlobalRequest.GlobalRequestResponse>) {
                self.requests.append(request)
                let port = self.port
                self.port = nil
                promise.succeed(.init(boundPort: port))
            }
        }

        let customDelegate = CustomGlobalRequestDelegate()
        var harness = TestHarness()
        harness.serverGlobalRequestDelegate = customDelegate

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        func helper(_ request: GlobalRequest.TCPForwardingRequest) throws -> GlobalRequest.GlobalRequestResponse {
            let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.GlobalRequestResponse.self)
            self.channel.clientSSHHandler?.sendTCPForwardingRequest(request, promise: promise)
            try self.channel.interactInMemory()
            return try promise.futureResult.wait()
        }

        // This delegate accepts things.
        let firstResponse = try helper(.listen(host: "localhost", port: 8765))
        let secondResponse = try helper(.cancel(host: "localhost", port: 8765))

        XCTAssertEqual(firstResponse, GlobalRequest.GlobalRequestResponse(boundPort: 0))
        XCTAssertEqual(secondResponse, GlobalRequest.GlobalRequestResponse(boundPort: nil))

        XCTAssertEqual(customDelegate.requests, [.listen(host: "localhost", port: 8765), .cancel(host: "localhost", port: 8765)])
    }

    func testGlobalRequestTooEarlyIsDelayed() throws {
        var completed = false
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.GlobalRequestResponse.self)
        promise.futureResult.whenComplete { _ in completed = true }

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))

        // Issue a forwarding request early. This should be queued.
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(.listen(host: "localhost", port: 2222), promise: promise)
        XCTAssertFalse(completed)

        // Activate. This will complete the forwarding request.
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertTrue(completed)
    }

    func testGlobalRequestsAreCancelledIfRemoved() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Enqueue a global request.
        var err: Error?
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.GlobalRequestResponse.self)
        promise.futureResult.whenFailure { error in err = error }
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(.listen(host: "localhost", port: 1234), promise: promise)
        XCTAssertNil(err)

        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(err as? ChannelError, .eof)
    }

    func testNeverStartedGlobalRequestsAreCancelledIfRemoved() throws {
        var err: Error?
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.GlobalRequestResponse.self)
        promise.futureResult.whenFailure { error in err = error }

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))

        // Enqueue a forwarding request
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(.listen(host: "localhost", port: 1234), promise: promise)
        XCTAssertNil(err)

        // Now close the channel.
        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(err as? ChannelError, .eof)
    }

    func testGlobalRequestAfterCloseFails() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Get an early ref to the handler.
        let handler = self.channel.clientSSHHandler

        // Close.
        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Enqueue a global request.
        var err: Error?
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.GlobalRequestResponse.self)
        promise.futureResult.whenFailure { error in err = error }
        handler?.sendTCPForwardingRequest(.listen(host: "localhost", port: 1234), promise: promise)
        XCTAssertEqual(err as? ChannelError, .ioOnClosedChannel)
    }
}
