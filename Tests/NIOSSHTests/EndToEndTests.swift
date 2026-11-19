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

enum EndToEndTestError: Error {
    case unableToCreateChildChannel
}

class BackToBackEmbeddedChannel {
    private(set) var client: EmbeddedChannel
    private(set) var server: EmbeddedChannel
    private var loop: EmbeddedEventLoop

    private(set) var activeServerChannels: [Channel]

    var clientSSHHandler: NIOSSHHandler? {
        try? self.client.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
    }

    var serverSSHHandler: NIOSSHHandler? {
        try? self.server.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
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

    func advanceTime(by increment: TimeAmount) {
        self.loop.advanceTime(by: increment)
    }

    func activate() throws {
        // A weird wrinkle of embedded channel is that it only properly activates on connect.
        try self.client.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
        try self.server.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
    }

    func configureWithHarness(_ harness: TestHarness) throws {
        let clientHandler = NIOSSHHandler(
            role: .client(
                .init(
                    userAuthDelegate: harness.clientAuthDelegate,
                    serverAuthDelegate: harness.clientServerAuthDelegate,
                    globalRequestDelegate: harness.clientGlobalRequestDelegate
                )
            ),
            allocator: self.client.allocator,
            inboundChildChannelInitializer: nil
        )
        let serverHandler = NIOSSHHandler(
            role: .server(
                .init(
                    hostKeys: harness.serverHostKeys,
                    userAuthDelegate: harness.serverAuthDelegate,
                    globalRequestDelegate: harness.serverGlobalRequestDelegate,
                    banner: harness.serverAuthBanner
                )
            ),
            allocator: self.server.allocator
        ) { channel, _ in
            self.activeServerChannels.append(channel)
            let boxedSelf = NIOLoopBound(self, eventLoop: channel.eventLoop)
            channel.closeFuture.whenComplete { _ in
                boxedSelf.value.activeServerChannels.removeAll(where: { $0 === channel })
            }
            return channel.eventLoop.makeSucceededFuture(())
        }

        try self.client.pipeline.syncOperations.addHandler(clientHandler)
        try self.server.pipeline.syncOperations.addHandler(serverHandler)
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

    var clientServerAuthDelegate: NIOSSHClientServerAuthenticationDelegate = AcceptAllHostKeysDelegate()

    var clientGlobalRequestDelegate: GlobalRequestDelegate?

    var serverAuthDelegate: NIOSSHServerUserAuthenticationDelegate = DenyThenAcceptDelegate(messagesToDeny: 0)

    var serverGlobalRequestDelegate: GlobalRequestDelegate?

    var serverHostKeys: [NIOSSHPrivateKey] = [.init(ed25519Key: .init())]

    var serverAuthBanner: SSHServerConfiguration.UserAuthBanner?
}

final class UserEventExpecter: ChannelInboundHandler {
    typealias InboundIn = Any

    var userEvents: [Any] = []

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        self.userEvents.append(event)
        context.fireUserInboundEventTriggered(event)
    }
}

final class PrivateKeyClientAuth: NIOSSHClientUserAuthenticationDelegate {
    private var key: NIOSSHPrivateKey?

    init(_ key: NIOSSHPrivateKey) {
        self.key = key
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.publicKey), let key = self.key else {
            nextChallengePromise.succeed(nil)
            return
        }

        self.key = nil
        nextChallengePromise.succeed(
            .init(username: "foo", serviceName: "ssh-connection", offer: .privateKey(.init(privateKey: key)))
        )
    }
}

final class ExpectPublicKeyAuth: NIOSSHServerUserAuthenticationDelegate {
    private var key: NIOSSHPublicKey

    init(_ key: NIOSSHPublicKey) {
        self.key = key
    }

    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .publicKey

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        guard case .publicKey(let actualKey) = request.request else {
            responsePromise.succeed(.failure)
            return
        }

        if actualKey.publicKey == self.key {
            responsePromise.succeed(.success)
        } else {
            responsePromise.succeed(.failure)
        }
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
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(userEventRecorder))

        func helper<Event: Equatable>(_ event: Event) {
            let clientSent = NIOLoopBoundBox(false, eventLoop: clientChannel.eventLoop)

            let promise = clientChannel.eventLoop.makePromise(of: Void.self)
            clientChannel.pipeline.syncOperations.triggerUserOutboundEvent(event, promise: promise)
            promise.futureResult.whenSuccess { clientSent.value = true }
            XCTAssertNoThrow(try self.channel.interactInMemory())

            XCTAssertTrue(clientSent.value)
            XCTAssertEqual(userEventRecorder.userEvents.last as? Event?, event)
        }

        helper(SSHChannelRequestEvent.ExecRequest(command: "uname -a", wantReply: true))
        helper(SSHChannelRequestEvent.EnvironmentRequest(wantReply: true, name: "foo", value: "bar"))
        helper(SSHChannelRequestEvent.ExitStatus(exitStatus: 5))
        helper(
            SSHChannelRequestEvent.PseudoTerminalRequest(
                wantReply: true,
                term: "vt100",
                terminalCharacterWidth: 80,
                terminalRowHeight: 24,
                terminalPixelWidth: 0,
                terminalPixelHeight: 0,
                terminalModes: .init([.ECHO: 5])
            )
        )
        helper(SSHChannelRequestEvent.ShellRequest(wantReply: true))
        helper(
            SSHChannelRequestEvent.ExitSignal(
                signalName: "ILL",
                errorMessage: "illegal instruction",
                language: "en",
                dumpedCore: true
            )
        )
        helper(SSHChannelRequestEvent.SubsystemRequest(subsystem: "file transfer", wantReply: false))
        helper(
            SSHChannelRequestEvent.WindowChangeRequest(
                terminalCharacterWidth: 0,
                terminalRowHeight: 0,
                terminalPixelWidth: 720,
                terminalPixelHeight: 480
            )
        )
        helper(SSHChannelRequestEvent.LocalFlowControlRequest(clientCanDo: true))
        helper(SSHChannelRequestEvent.SignalRequest(signal: "USR1"))
        helper(ChannelSuccessEvent())
        helper(ChannelFailureEvent())
    }

    func testGlobalRequestWithDefaultDelegate() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        func helper(_ request: GlobalRequest.TCPForwardingRequest) throws -> GlobalRequest.TCPForwardingResponse? {
            let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
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

            func tcpForwardingRequest(
                _ request: GlobalRequest.TCPForwardingRequest,
                handler: NIOSSHHandler,
                promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>
            ) {
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

        func helper(_ request: GlobalRequest.TCPForwardingRequest) throws -> GlobalRequest.TCPForwardingResponse? {
            let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
            self.channel.clientSSHHandler?.sendTCPForwardingRequest(request, promise: promise)
            try self.channel.interactInMemory()
            return try promise.futureResult.wait()
        }

        // This delegate accepts things.
        let firstResponse = try helper(.listen(host: "localhost", port: 8765))
        let secondResponse = try helper(.cancel(host: "localhost", port: 8765))

        XCTAssertEqual(firstResponse, GlobalRequest.TCPForwardingResponse(boundPort: 0))
        XCTAssertEqual(secondResponse, GlobalRequest.TCPForwardingResponse(boundPort: nil))

        XCTAssertEqual(
            customDelegate.requests,
            [.listen(host: "localhost", port: 8765), .cancel(host: "localhost", port: 8765)]
        )
    }

    func testUnknownGlobalRequestCanTriggerResponse() throws {
        // This test verifies that, when the boolean `wantReply` is true, an error reply is sent back

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Force unwrap is used, because this is a test and the handler must exist
        let clientSSHHandler = self.channel.clientSSHHandler!

        // The arbitrary number of 12 has no meaning here
        // What _is_ important is that the amount of added bytes is greater than 0
        var randomPayload = self.channel.client.allocator.buffer(capacity: 12)
        randomPayload.writeBytes(Array(randomBytes: 12))

        let firstReply = self.channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        clientSSHHandler.sendGlobalRequestMessage(
            .init(wantReply: true, type: .unknown("test", randomPayload)),
            promise: firstReply
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertThrowsError(try firstReply.futureResult.wait())

        let secondReply = self.channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        clientSSHHandler.sendGlobalRequestMessage(
            .init(wantReply: false, type: .unknown("test", randomPayload)),
            promise: secondReply
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertNil(try secondReply.futureResult.wait())
    }

    func testGlobalRequestTooEarlyIsDelayed() throws {
        let completed = NIOLoopBoundBox(false, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenComplete { _ in completed.value = true }

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))

        // Issue a forwarding request early. This should be queued.
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(
            .listen(host: "localhost", port: 2222),
            promise: promise
        )
        XCTAssertFalse(completed.value)

        // Activate. This will complete the forwarding request.
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertTrue(completed.value)
    }

    func testGlobalRequestsAreCancelledIfRemoved() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Enqueue a global request.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err.value = error }
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(
            .listen(host: "localhost", port: 1234),
            promise: promise
        )
        XCTAssertNil(err.value)

        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(err.value as? ChannelError, .eof)
    }

    func testNeverStartedGlobalRequestsAreCancelledIfRemoved() throws {
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err.value = error }

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))

        // Enqueue a forwarding request
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(
            .listen(host: "localhost", port: 1234),
            promise: promise
        )
        XCTAssertNil(err.value)

        // Now close the channel.
        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(err.value as? ChannelError, .eof)
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
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err.value = error }
        handler?.sendTCPForwardingRequest(.listen(host: "localhost", port: 1234), promise: promise)
        XCTAssertEqual(err.value as? ChannelError, .ioOnClosedChannel)
    }

    func testSecureEnclaveKeys() throws {
        // This is a quick end-to-end test that validates that we support secure enclave private keys
        // on appropriate platforms.
        #if canImport(Darwin)
        // If we can't create this key, we skip the test.
        let key: NIOSSHPrivateKey
        do {
            key = try .init(secureEnclaveP256Key: .init())
        } catch {
            return
        }

        // We use the Secure Enclave keys for everything, just because we can.
        var harness = TestHarness()
        harness.serverHostKeys = [key]
        harness.clientAuthDelegate = PrivateKeyClientAuth(key)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(key.publicKey)

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel, again, just because we can.
        _ = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
        #endif
    }

    func testSupportClientInitiatedRekeying() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate re-keying on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._rekey())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // We should be able to send a message here.
        XCTAssertEqual(self.channel.activeServerChannels.count, 0)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testSupportServerInitiatedRekeying() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate re-keying on the server.
        XCTAssertNoThrow(try self.channel.serverSSHHandler!._rekey())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // We should be able to send a message here.
        XCTAssertEqual(self.channel.activeServerChannels.count, 0)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testWindowAdjustRefusedDuringKeyExchangeIsReissuedAfterExhaustingWindow() throws {
        try self.channel.configureWithHarness(TestHarness())
        try self.channel.activate()
        try self.channel.interactInMemory()

        let readRecorder = ReadRecordingHandler()
        var clientChannel = Optional<Channel>.none
        self.channel.clientSSHHandler?.createChannel { channel, _ in
            clientChannel = channel
            do {
                try channel.pipeline.syncOperations.addHandler(readRecorder)
            } catch {
                return channel.eventLoop.makeFailedFuture(error)
            }
            return channel.setOption(ChannelOptions.autoRead, value: false)
        }
        try self.channel.interactInMemory()
        let client = try XCTUnwrap(clientChannel)
        let server = try XCTUnwrap(self.channel.activeServerChannels.first)

        func bytesRead() -> Int {
            readRecorder.reads.reduce(0) { total, read in
                guard case .byteBuffer(let buffer) = read.data else {
                    return total
                }
                return total + buffer.readableBytes
            }
        }

        // Exhaust the peer's entire window while the client buffers the data without reading.
        let windowSize = Constants.defaultMaximumChannelPacketSize * Constants.channelWindowSizePacketMultiple
        server.writeAndFlush(
            SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(repeating: 1, count: windowSize))),
            promise: nil
        )
        try self.channel.interactInMemory()
        XCTAssertEqual(bytesRead(), 0)

        // Drain every buffered byte during rekeying, when all window adjustments are refused.
        try self.channel.clientSSHHandler!._rekey()
        client.read()
        XCTAssertEqual(bytesRead(), windowSize)
        try self.channel.interactInMemory()

        // Rekeying has finished, but the peer has no window left. Even one more byte requires a new
        // window adjustment, and there are no buffered reads left to trigger that adjustment.
        server.writeAndFlush(
            SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(repeating: 2, count: 1))),
            promise: nil
        )
        try client.setOption(ChannelOptions.autoRead, value: true).wait()
        client.read()
        try self.channel.interactInMemory()

        XCTAssertEqual(
            bytesRead(),
            windowSize + 1,
            "Rekeying must restore the exhausted window even when no further reads can trigger an adjustment"
        )
    }

    /// A child channel credits its window increment before it writes the CHANNEL_WINDOW_ADJUST. While a key
    /// exchange is in progress the connection refuses channel messages, so that adjust never reaches the peer.
    /// If the increment stays credited, we believe the peer still has a full window, so we never send another
    /// adjust, while the peer runs out of window: the channel stalls forever. The refused adjust must instead be
    /// re-issued once the exchange is over, so the peer can keep sending beyond its initial window.
    ///
    /// The rekey here is client-initiated; a server-initiated one (e.g. OpenSSH's RekeyLimit) refuses the adjust
    /// the same way, as the refusal does not depend on which side started the exchange.
    func testWindowAdjustRefusedDuringKeyExchangeIsReissuedAfterwards() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // The client channel only reads when asked to, so that we control when it emits its window adjust.
        let readRecorder = ReadRecordingHandler()
        var clientChannel = Optional<Channel>.none
        self.channel.clientSSHHandler?.createChannel { channel, _ in
            clientChannel = channel
            do {
                try channel.pipeline.syncOperations.addHandler(readRecorder)
            } catch {
                return channel.eventLoop.makeFailedFuture(error)
            }
            return channel.setOption(ChannelOptions.autoRead, value: false)
        }
        XCTAssertNoThrow(try self.channel.interactInMemory())
        guard let clientChannel = clientChannel, let serverChannel = self.channel.activeServerChannels.first else {
            XCTFail("Channels not created")
            return
        }

        func bytesRead() -> Int {
            readRecorder.reads.reduce(0) { total, read in
                guard case .byteBuffer(let buffer) = read.data else {
                    return total
                }
                return total + buffer.readableBytes
            }
        }

        let targetWindowSize = Constants.defaultMaximumChannelPacketSize * Constants.channelWindowSizePacketMultiple

        // The server uses most of the client's window, and the client buffers it all without reading. As with most
        // real traffic, the messages don't divide the window evenly, so the increment the client emits once it
        // has read half the window is a little larger than half the window.
        let messageSize = 100_000
        let firstBurstSize = messageSize * 60
        XCTAssertLessThan(firstBurstSize, targetWindowSize)
        XCTAssertNotEqual((targetWindowSize / 2) % messageSize, 0)
        for _ in 0..<(firstBurstSize / messageSize) {
            serverChannel.write(
                SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(repeating: 1, count: messageSize))),
                promise: nil
            )
        }
        serverChannel.flush()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(bytesRead(), 0)

        // The client starts a key exchange, then reads. Reading crosses the half-window threshold, so the client
        // emits a window adjust, which the connection refuses because the key exchange is in progress.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._rekey())
        clientChannel.read()
        XCTAssertEqual(bytesRead(), firstBurstSize)

        // Complete the key exchange.
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // The server now sends a full window more. Only the rest of the initial window is left, so everything
        // beyond it can only arrive if the client re-issues the adjust it lost during the key exchange.
        let secondBurstSize = targetWindowSize
        serverChannel.writeAndFlush(
            SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(repeating: 2, count: secondBurstSize))),
            promise: nil
        )
        XCTAssertNoThrow(try clientChannel.setOption(ChannelOptions.autoRead, value: true).wait())
        clientChannel.read()
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertEqual(
            bytesRead(),
            firstBurstSize + secondBurstSize,
            "The peer's window was lost with the adjust refused during the key exchange: the channel stalled"
        )
    }

    func testDelayedHostKeyValidation() throws {
        class DelayedValidationDelegate: NIOSSHClientServerAuthenticationDelegate {
            var validationCount = 0

            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                // Short delay here, but we'll be forced to wait.
                let eventLoopSelf = NIOLoopBoundBox(
                    self,
                    eventLoop: validationCompletePromise.futureResult.eventLoop
                )
                validationCompletePromise.futureResult.eventLoop.scheduleTask(in: .milliseconds(100)) {
                    eventLoopSelf.value.validationCount += 1
                    validationCompletePromise.succeed(())
                }
            }
        }

        let delegate = DelayedValidationDelegate()
        var harness = TestHarness()
        harness.clientServerAuthDelegate = delegate

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // This will not be active yet! Advance time and interact again.
        XCTAssertEqual(delegate.validationCount, 0)
        self.channel.advanceTime(by: .milliseconds(100))
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(delegate.validationCount, 1)

        // We should be able to send a message here.
        XCTAssertEqual(self.channel.activeServerChannels.count, 0)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testHostKeyRejection() throws {
        enum TestError: Error {
            case bang
        }

        struct RejectDelegate: NIOSSHClientServerAuthenticationDelegate {
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                validationCompletePromise.fail(TestError.bang)
            }
        }

        let errorCatcher = ErrorLoggingHandler()
        var harness = TestHarness()
        harness.clientServerAuthDelegate = RejectDelegate()

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(errorCatcher))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertThrowsError(try self.channel.interactInMemory()) { error in
            XCTAssertEqual(error as? TestError, .bang)
        }

        XCTAssertEqual(errorCatcher.errors.count, 1)
        XCTAssertEqual(errorCatcher.errors.first as? TestError, .bang)
    }

    func testCreateChannelBeforeIncompleteHandshakeFails() throws {
        enum TestError: Error {
            case bang
        }

        struct RejectDelegate: NIOSSHClientServerAuthenticationDelegate {
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                validationCompletePromise.fail(TestError.bang)
            }
        }

        var harness = TestHarness()
        harness.clientServerAuthDelegate = RejectDelegate()

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(ErrorClosingHandler()))

        // Get an early ref to the handler and try to create a child channel.
        let handler = self.channel.clientSSHHandler

        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err.value = error }
        handler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        XCTAssertNil(err.value)

        // Activation errors.
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertThrowsError(try self.channel.interactInMemory()) { error in
            XCTAssertEqual(error as? TestError, .bang)
        }
        self.channel.run()
        XCTAssertEqual(err.value as? ChannelError?, .eof)
    }

    func testCreateChannelAfterDisconnectFailsWithEventLoopTick() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate disconnection on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._disconnect())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Attempting to create a child channel should immediately fail.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err.value = error }
        self.channel.clientSSHHandler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        self.channel.run()

        XCTAssertNotNil(err.value)
        XCTAssertEqual((err.value as? NIOSSHError)?.type, .creatingChannelAfterClosure)
    }

    func testCreateChannelAfterDisconnectFailsWithoutEventLoopTick() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate disconnection on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._disconnect())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Attempting to create a child channel should immediately fail.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err.value = error }
        self.channel.clientSSHHandler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        self.channel.run()

        XCTAssertNotNil(err.value)
        XCTAssertEqual((err.value as? NIOSSHError)?.type, .creatingChannelAfterClosure)
    }

    func testHandshakeSuccess() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            let promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                if event is UserAuthSuccessEvent {
                    self.promise.succeed(())
                }
            }
        }

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        let harness = TestHarness()

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertNoThrow(try promise.futureResult.wait())
    }

    func testServerDoesNotSendBanner() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            var promise: EventLoopPromise<Void>?

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                guard let promise = self.promise else { return }
                self.promise = nil

                if event is NIOUserAuthBannerEvent {
                    promise.fail(HandshakeFailure.missingBanner)
                } else if event is UserAuthSuccessEvent {
                    promise.succeed(())
                }
            }

            enum HandshakeFailure: Error {
                case missingBanner
            }
        }

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        var harness = TestHarness()
        harness.serverAuthBanner = nil

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertNoThrow(try promise.futureResult.wait())
    }

    func testCorrectBannerReceived() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            static let expectedAuthBannerMessage = "This is a demo user auth banner."
            static let expectedAuthBannerLanguageTag = "en"

            var promise: EventLoopPromise<(String, String)>?

            init(promise: EventLoopPromise<(String, String)>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                guard let promise = self.promise else { return }
                self.promise = nil

                if let event = event as? NIOUserAuthBannerEvent {
                    promise.succeed((event.message, event.languageTag))
                } else if event is UserAuthSuccessEvent {
                    promise.fail(HandshakeFailure.missingBanner)
                }
            }

            enum HandshakeFailure: Error {
                case missingBanner
            }
        }

        let promise = self.channel.client.eventLoop.makePromise(of: (String, String).self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        var harness = TestHarness()
        harness.serverAuthBanner = .init(
            message: ClientHandshakeHandler.expectedAuthBannerMessage,
            languageTag: ClientHandshakeHandler.expectedAuthBannerLanguageTag
        )

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        var banner = ("", "")
        XCTAssertNoThrow(banner = try promise.futureResult.wait())
        XCTAssertEqual(banner.0, ClientHandshakeHandler.expectedAuthBannerMessage)
        XCTAssertEqual(banner.1, ClientHandshakeHandler.expectedAuthBannerLanguageTag)
    }

    func testHandshakeFailure() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            let promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func errorCaught(context: ChannelHandlerContext, error: Error) {
                self.promise.fail(error)
            }
        }

        enum TestError: Error {
            case bang
        }

        struct BadPasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
            func nextAuthenticationType(
                availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
            ) {
                nextChallengePromise.fail(TestError.bang)
            }
        }

        var harness = TestHarness()
        harness.clientAuthDelegate = BadPasswordDelegate()

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertThrowsError(try promise.futureResult.wait()) { error in
            XCTAssertEqual(error as? TestError, TestError.bang)
        }
    }
}
