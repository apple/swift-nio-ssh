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

import NIO
@testable import NIOSSH
import XCTest

/// The dummy delegate is used to record calls from the multiplexer to the handler.
///
/// This reduces the testing surface area somewhat, which greatly helps us to test the
/// implementation of the multiplexer and child channels.
final class DummyDelegate: SSHMultiplexerDelegate {
    var _channel: EmbeddedChannel = EmbeddedChannel()

    var writes: MarkedCircularBuffer<(SSHMessage, EventLoopPromise<Void>?)> = MarkedCircularBuffer(initialCapacity: 8)

    init() {
        // This has the effect of activating the channel, which we need for the other tests.
        try! self._channel.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
    }

    var channel: Channel? {
        self._channel
    }

    var allocator: ByteBufferAllocator {
        self._channel.allocator
    }

    func writeFromChildChannel(_ message: SSHMessage, _ promise: EventLoopPromise<Void>?) {
        self.writes.append((message, promise))
        self.channel?.write(message, promise: promise)
    }

    func flushFromChildChannel() {
        self.writes.mark()
        self.channel?.flush()
    }
}

final class ErrorLoggingHandler: ChannelInboundHandler {
    typealias InboundIn = Any
    typealias InboundOut = Any

    var errors: [Error] = []

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.errors.append(error)
        context.fireErrorCaught(error)
    }
}

final class ErrorClosingHandler: ChannelInboundHandler {
    typealias InboundIn = Any
    typealias InboundOut = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
        context.fireErrorCaught(error)
    }
}

final class ReadCountingHandler: ChannelOutboundHandler {
    typealias OutboundIn = Any
    typealias OutboundOut = Any

    var readCount = 0

    func read(context: ChannelHandlerContext) {
        self.readCount += 1
        context.read()
    }
}

final class ReadRecordingHandler: ChannelInboundHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = SSHChannelData

    var reads: [SSHChannelData] = []

    var channel: Channel?

    func handlerAdded(context: ChannelHandlerContext) {
        self.channel = context.channel
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.channel = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self.reads.append(self.unwrapInboundIn(data))
        context.fireChannelRead(data)
    }
}

final class ChannelInactiveRecorder: ChannelInboundHandler {
    typealias InboundIn = Any
    typealias InboundOut = Any

    var seenInactive: Bool = false

    func channelInactive(context: ChannelHandlerContext) {
        XCTAssertFalse(self.seenInactive)
        self.seenInactive = true
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        XCTAssertTrue(self.seenInactive)
    }
}

final class EOFRecorder: ChannelInboundHandler {
    typealias InboundIn = Any
    typealias InboundOut = Any

    var seenEOF = false

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        XCTAssertFalse(self.seenEOF)
        context.fireChannelRead(data)
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as ChannelEvent where event == .inputClosed:
            XCTAssertFalse(self.seenEOF)
            self.seenEOF = true

        default:
            break
        }

        context.fireUserInboundEventTriggered(event)
    }
}

private enum MultiplexerTestError: Error {
    case rejected
}

final class ChildChannelMultiplexerTests: XCTestCase {
    struct TestHarness {
        var delegate: DummyDelegate

        var multiplexer: SSHChannelMultiplexer

        var eventLoop: EmbeddedEventLoop {
            self.delegate._channel.embeddedEventLoop
        }

        func finish() {
            self.multiplexer.parentChannelInactive()
            self.multiplexer.parentHandlerRemoved()
            self.eventLoop.run()
        }

        var flushedMessages: [SSHMessage] {
            guard let markIndex = self.delegate.writes.markedElementIndex else {
                return []
            }

            return self.delegate.writes.prefix(through: markIndex).map { $0.0 }
        }

        /// A non-crashing way to ask for the message number.
        func flushedMessage(_ number: Int) -> SSHMessage? {
            self.flushedMessages.dropFirst(number).first
        }
    }

    private func harness(_ initializer: SSHChildChannel.Initializer? = nil) -> TestHarness {
        let delegate = DummyDelegate()
        let multiplexer = SSHChannelMultiplexer(delegate: delegate, allocator: delegate.allocator, childChannelInitializer: initializer)
        return TestHarness(delegate: delegate, multiplexer: multiplexer)
    }

    private func harnessForbiddingInboundChannels() -> TestHarness {
        self.harness { channel, _ in
            XCTFail("No inbound channel creation is allowed")
            return channel.eventLoop.makeFailedFuture(MultiplexerTestError.rejected)
        }
    }

    private func openRequest(channelID: UInt32, initialWindowSize: UInt32 = 1 << 24, maxPacketSize: UInt32 = 1 << 24) -> SSHMessage {
        .channelOpen(.init(type: .session,
                           senderChannel: channelID,
                           initialWindowSize: initialWindowSize,
                           maximumPacketSize: maxPacketSize))
    }

    private func openConfirmation(originalChannelID: UInt32, peerChannelID: UInt32, initialWindowSize: UInt32 = 1 << 24, maxPacketSize: UInt32 = 1 << 24) -> SSHMessage {
        .channelOpenConfirmation(.init(recipientChannel: originalChannelID,
                                       senderChannel: peerChannelID,
                                       initialWindowSize: initialWindowSize,
                                       maximumPacketSize: maxPacketSize))
    }

    private func openFailure(originalChannelID: UInt32, reasonCode: UInt32) -> SSHMessage {
        .channelOpenFailure(.init(recipientChannel: originalChannelID, reasonCode: reasonCode, description: "", language: ""))
    }

    private func data(peerChannelID: UInt32, data: ByteBuffer) -> SSHMessage {
        .channelData(.init(recipientChannel: peerChannelID, data: data))
    }

    private func close(peerChannelID: UInt32) -> SSHMessage {
        .channelClose(.init(recipientChannel: peerChannelID))
    }

    private func eof(peerChannelID: UInt32) -> SSHMessage {
        .channelEOF(.init(recipientChannel: peerChannelID))
    }

    private func windowAdjust(peerChannelID: UInt32, increment: UInt32) -> SSHMessage {
        .channelWindowAdjust(.init(recipientChannel: peerChannelID, bytesToAdd: increment))
    }

    @discardableResult
    func assertChannelOpen(_ message: SSHMessage?) -> UInt32? {
        switch message {
        case .some(.channelOpen(let message)):
            XCTAssertEqual(message.maximumPacketSize, 1 << 24)
            XCTAssertEqual(message.initialWindowSize, 1 << 24)
            return message.senderChannel

        case let fallback:
            XCTFail("Unexpected message: \(String(describing: fallback))")
            return nil
        }
    }

    @discardableResult
    func assertChannelOpenConfirmation(_ message: SSHMessage?, recipientChannel: UInt32) -> UInt32? {
        switch message {
        case .some(.channelOpenConfirmation(let message)):
            XCTAssertEqual(message.recipientChannel, recipientChannel)
            XCTAssertEqual(message.maximumPacketSize, 1 << 24)
            XCTAssertEqual(message.initialWindowSize, 1 << 24)
            return message.senderChannel

        case let fallback:
            XCTFail("Unexpected message: \(String(describing: fallback))")
            return nil
        }
    }

    func assertChannelOpenFailure(_ message: SSHMessage?, recipientChannel: UInt32) {
        switch message {
        case .some(.channelOpenFailure(let message)):
            XCTAssertEqual(message.recipientChannel, recipientChannel)
            XCTAssertEqual(message.reasonCode, 2)

        case let fallback:
            XCTFail("Unexpected message: \(String(describing: fallback))")
        }
    }

    func assertChannelClose(_ message: SSHMessage?, recipientChannel: UInt32) {
        switch message {
        case .some(.channelClose(let message)):
            XCTAssertEqual(message.recipientChannel, recipientChannel)

        case let fallback:
            XCTFail("Unexpected message: \(String(describing: fallback))")
        }
    }

    func assertChannelData(_ message: SSHMessage?, data: ByteBuffer, recipientChannel: UInt32) {
        switch message {
        case .some(.channelData(let message)):
            XCTAssertEqual(message.data, data)
            XCTAssertEqual(message.recipientChannel, recipientChannel)

        case let fallback:
            XCTFail("Unexpected message: \(String(describing: fallback))")
        }
    }

    func assertChannelExtendedData(_ message: SSHMessage?, type: SSHMessage.ChannelExtendedDataMessage.Code, data: ByteBuffer, recipientChannel: UInt32) {
        switch message {
        case .some(.channelExtendedData(let message)):
            XCTAssertEqual(message.dataTypeCode, type)
            XCTAssertEqual(message.data, data)
            XCTAssertEqual(message.recipientChannel, recipientChannel)

        case let fallback:
            XCTFail("Unexpected message: \(String(describing: fallback))")
        }
    }

    func assertChannelRequest(_ message: SSHMessage?, type: SSHMessage.ChannelRequestMessage.RequestType, recipientChannel: UInt32, wantReply: Bool) {
        switch message {
        case .some(.channelRequest(let message)):
            XCTAssertEqual(message.type, type)
            XCTAssertEqual(message.recipientChannel, recipientChannel)
            XCTAssertEqual(message.wantReply, wantReply)

        case let fallback:
            XCTFail("Unexpected message: \(String(describing: fallback))")
        }
    }

    func assertWindowAdjust(_ message: SSHMessage?, recipientChannel: UInt32, delta: UInt32) {
        switch message {
        case .some(.channelWindowAdjust(let message)):
            XCTAssertEqual(message.recipientChannel, recipientChannel)
            XCTAssertEqual(message.bytesToAdd, delta)

        case let fallback:
            XCTFail("Unexpected message: \(String(describing: fallback))")
        }
    }

    func assertEOF(_ message: SSHMessage?, recipientChannel: UInt32) {
        switch message {
        case .some(.channelEOF(let message)):
            XCTAssertEqual(message.recipientChannel, recipientChannel)

        case let fallback:
            XCTFail("Unexpected message: \(String(describing: fallback))")
        }
    }

    func testBasicInboundChannelCreation() throws {
        var creationCount = 0
        let harness = self.harness { channel, _ in
            creationCount += 1
            return channel.eventLoop.makeSucceededFuture(())
        }
        defer {
            harness.finish()
        }

        XCTAssertEqual(creationCount, 0)
        XCTAssertEqual(harness.flushedMessages.count, 0)

        let openRequest = self.openRequest(channelID: 1)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(openRequest))
        XCTAssertEqual(creationCount, 1)
        XCTAssertEqual(harness.flushedMessages.count, 1)
        XCTAssertNil(harness.delegate.writes.first?.1)

        self.assertChannelOpenConfirmation(harness.flushedMessages.first, recipientChannel: 1)
    }

    func testRejectInboundChannelCreation() {
        let errorLogger = ErrorLoggingHandler()

        let harness = self.harness { channel, _ in
            channel.pipeline.addHandler(errorLogger).flatMap {
                channel.eventLoop.makeFailedFuture(MultiplexerTestError.rejected)
            }
        }
        defer {
            harness.finish()
        }

        XCTAssertEqual(errorLogger.errors.count, 0)
        XCTAssertEqual(harness.flushedMessages.count, 0)

        let openRequest = self.openRequest(channelID: 2)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(openRequest))
        XCTAssertEqual(errorLogger.errors.count, 1)
        XCTAssertEqual(harness.flushedMessages.count, 1)

        self.assertChannelOpenFailure(harness.flushedMessages.first, recipientChannel: 2)
        XCTAssertNil(harness.delegate.writes.first?.1)

        switch errorLogger.errors.first {
        case .some(let error as NIOSSHError):
            XCTAssertEqual(error.type, .channelSetupRejected)

        case let fallback:
            XCTFail("Unexpected error: \(String(describing: fallback))")
        }
    }

    func testOutboundChannelCreation() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Channel doesn't go active until we get a response.
        XCTAssertFalse(channel.isActive)
        XCTAssertTrue(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 1)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)

        // Closing is delayed until we receive a response to our outbound message.
        var didClose = false
        channel.close().whenComplete { _ in didClose = true }
        XCTAssertFalse(didClose)
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Now we drop in an open confirmation. This immediately triggers a close message.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))
        XCTAssertFalse(didClose)
        XCTAssertEqual(harness.flushedMessages.count, 2)
        self.assertChannelClose(harness.flushedMessages.last, recipientChannel: 1)

        // We get a response
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.close(peerChannelID: channelID!)))

        // No longer active.
        XCTAssertTrue(didClose)
        XCTAssertFalse(channel.isActive)
    }

    func testBetterOutboundChannelCreation() {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Channel doesn't go active until we get a response.
        XCTAssertFalse(channel.isActive)
        XCTAssertTrue(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 1)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)

        // Now we drop in an open confirmation. No new messages, but the channel is open.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))
        XCTAssertTrue(channel.isActive)
        XCTAssertTrue(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Closing will not happen straight away. We'll send a channel close message.
        var closed = false
        channel.close().whenComplete { result in
            closed = true

            if case .failure(let error) = result {
                XCTFail("Closing hit error: \(error)")
            }
        }
        XCTAssertFalse(closed)
        XCTAssertEqual(harness.flushedMessages.count, 2)
        self.assertChannelClose(harness.flushedMessages.last, recipientChannel: 1)
        XCTAssertTrue(channel.isActive)

        // But we need one back.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.close(peerChannelID: channelID!)))

        // No longer active.
        XCTAssertTrue(closed)
        XCTAssertFalse(channel.isActive)
    }

    func testCloseBeforeActiveOnOutboundChannelWhenReceivingFailure() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Channel doesn't go active until we get a response.
        XCTAssertFalse(channel.isActive)
        XCTAssertTrue(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 1)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)

        // Closing is delayed until we receive a response to our outbound message.
        var closeError: Error?
        channel.close().whenFailure { closeError = $0 }
        XCTAssertNil(closeError)
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Now we drop in an open failure. This does not trigger a close message.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openFailure(originalChannelID: channelID!, reasonCode: 2)))
        XCTAssertNotNil(closeError)
        XCTAssertEqual(harness.flushedMessages.count, 1)

        if let error = closeError {
            XCTAssertEqual((error as? NIOSSHError)?.type, .channelSetupRejected)
        }

        // No longer active.
        XCTAssertFalse(channel.isActive)
    }

    func testFailingOutboundChannelInitializerDoesNotDoIO() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        var childChannel: Channel?
        var childPromise: EventLoopPromise<Void>?
        var childCloseError: Error?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            childPromise = channel.eventLoop.makePromise(of: Void.self)
            return childPromise!.futureResult
        }

        guard let channel = childChannel, let promise = childPromise else {
            XCTFail("Did not create child channel")
            return
        }

        channel.closeFuture.whenFailure { error in childCloseError = error }

        // Channel doesn't go active yet.
        XCTAssertFalse(channel.isActive)
        XCTAssertTrue(channel.isWritable)
        XCTAssertNil(childCloseError)
        XCTAssertEqual(harness.flushedMessages.count, 0)

        promise.fail(MultiplexerTestError.rejected)

        // No IO!
        harness.eventLoop.run()
        XCTAssertFalse(channel.isActive)
        XCTAssertTrue(channel.isWritable)
        XCTAssertEqual(childCloseError as? MultiplexerTestError, .rejected)
        XCTAssertEqual(harness.flushedMessages.count, 0)
    }

    func testWritesAreQueuedUntilActivity() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        var buffer = harness.delegate._channel.allocator.buffer(capacity: 1024)
        buffer.writeString("Hello from the unit tests!")

        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            channel.write(SSHChannelData(type: .channel, data: .byteBuffer(buffer)), promise: nil)
            channel.write(SSHChannelData(type: .stdErr, data: .byteBuffer(buffer)), promise: nil)
            channel.flush()
            return channel.eventLoop.makeSucceededFuture(())
        }

        XCTAssertEqual(harness.flushedMessages.count, 1)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)

        // Open the channel
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))

        // The writes should fire
        XCTAssertEqual(harness.flushedMessages.count, 3)
        self.assertChannelData(harness.flushedMessage(1), data: buffer, recipientChannel: 1)
        self.assertChannelExtendedData(harness.flushedMessage(2), type: .stderr, data: buffer, recipientChannel: 1)
    }

    func testUserOutboundEventsAreQueuedUntilActivity() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            channel.triggerUserOutboundEvent(SSHChannelRequestEvent.EnvironmentRequest(wantReply: false, name: "HOME", value: "/usr/root"), promise: nil)
            channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ExecRequest(command: "uname", wantReply: false), promise: nil)
            return channel.eventLoop.makeSucceededFuture(())
        }

        XCTAssertEqual(harness.flushedMessages.count, 1)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)

        // Open the channel
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))

        // The user event should fire.
        XCTAssertEqual(harness.flushedMessages.count, 3)
        self.assertChannelRequest(harness.flushedMessage(1), type: .env("HOME", "/usr/root"), recipientChannel: 1, wantReply: false)
        self.assertChannelRequest(harness.flushedMessage(2), type: .exec("uname"), recipientChannel: 1, wantReply: false)
    }

    func testReadsAreDelayedUntilRead() throws {
        let readRecorder = ReadRecordingHandler()

        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        // We're going to deliver a series of data messages, which should not be processed until read is called.
        var buffer = harness.delegate._channel.allocator.buffer(capacity: 1024)
        buffer.writeString("Hello from the unit tests")

        // Let's create a channel.
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            channel.setOption(ChannelOptions.autoRead, value: false).flatMap {
                channel.pipeline.addHandler(readRecorder)
            }
        }

        XCTAssertEqual(harness.flushedMessages.count, 1)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))
        XCTAssertEqual(readRecorder.reads, [])

        // Now we're going to deliver some data. These should not propagate into the channel.
        for _ in 0 ..< 5 {
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!, data: buffer)))
        }

        // No I/O
        XCTAssertEqual(readRecorder.reads, [])
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Call read. The messages should be delivered.
        readRecorder.channel?.read()
        XCTAssertEqual(readRecorder.reads, Array(repeating: .init(type: .channel, data: .byteBuffer(buffer)), count: 5))
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Issue another read call. Nothing happens.
        readRecorder.channel?.read()
        readRecorder.channel?.read()
        readRecorder.channel?.read()
        XCTAssertEqual(readRecorder.reads, Array(repeating: .init(type: .channel, data: .byteBuffer(buffer)), count: 5))
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Delivering two new messages causes one read.
        for _ in 0 ..< 2 {
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!, data: buffer)))
            harness.multiplexer.parentChannelReadComplete()
        }
        XCTAssertEqual(readRecorder.reads, Array(repeating: .init(type: .channel, data: .byteBuffer(buffer)), count: 6))
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // And get it all through now.
        readRecorder.channel?.read()
        XCTAssertEqual(readRecorder.reads, Array(repeating: .init(type: .channel, data: .byteBuffer(buffer)), count: 7))
        XCTAssertEqual(harness.flushedMessages.count, 1)
    }

    func testParentChannelInactiveDisablesChildChannels() {
        var childChannels: [Channel] = []
        let harness = self.harness { channel, _ in
            childChannels.append(channel)
            return channel.pipeline.addHandler(ChannelInactiveRecorder())
        }
        defer {
            harness.finish()
        }

        XCTAssertEqual(childChannels.count, 0)
        XCTAssertEqual(harness.flushedMessages.count, 0)

        // Create a few child channels.
        for channelID in 1 ... 5 {
            let openRequest = self.openRequest(channelID: UInt32(channelID))
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(openRequest))
            XCTAssertEqual(childChannels.count, channelID)
            XCTAssertEqual(harness.flushedMessages.count, channelID)
        }

        XCTAssertEqual(harness.flushedMessages.count, 5)

        XCTAssertTrue(childChannels.allSatisfy { $0.isActive })

        // Claim the parent has gone inactive. All should go inactive.
        harness.multiplexer.parentChannelInactive()

        // They send no messages.
        XCTAssertTrue(childChannels.allSatisfy { !$0.isActive })
        XCTAssertEqual(harness.flushedMessages.count, 5)
    }

    func testClosingClosedChannelsDoesntHurt() throws {
        var childChannels: [Channel] = []
        let harness = self.harness { channel, _ in
            childChannels.append(channel)
            return channel.pipeline.addHandler(ChannelInactiveRecorder())
        }
        defer {
            harness.finish()
        }

        XCTAssertEqual(childChannels.count, 0)
        XCTAssertEqual(harness.flushedMessages.count, 0)

        // Create a few child channels, and close them immediately.
        for channelID in 1 ... 5 {
            let openRequest = self.openRequest(channelID: UInt32(channelID))
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(openRequest))
            XCTAssertEqual(childChannels.count, channelID)
            XCTAssertEqual(harness.flushedMessages.count, channelID)

            let peerChannelID = self.assertChannelOpenConfirmation(harness.flushedMessages.last, recipientChannel: UInt32(channelID))
            let close = self.close(peerChannelID: peerChannelID!)
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(close))
        }

        XCTAssertEqual(harness.flushedMessages.count, 5)

        // All channels are already inactive, but still have their inactive recorder (and so have not seen an event loop tick).
        XCTAssertTrue(childChannels.allSatisfy { !$0.isActive })
        XCTAssertTrue(childChannels.allSatisfy { (try? $0.pipeline.handler(type: ChannelInactiveRecorder.self).wait()) != nil })

        // Claim the parent has gone inactive. All should go inactive.
        harness.multiplexer.parentChannelInactive()

        // Now run the loop, confirm they're gone.
        harness.eventLoop.run()
        XCTAssertTrue(childChannels.allSatisfy { !$0.isActive })
        XCTAssertTrue(childChannels.allSatisfy { (try? $0.pipeline.handler(type: ChannelInactiveRecorder.self).wait()) == nil })

        // And they didn't say anything.
        XCTAssertEqual(harness.flushedMessages.count, 5)
    }

    func testMultiplexerDropsWritesAfterItLosesTheHandler() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Activate the channel.
        XCTAssertEqual(harness.flushedMessages.count, 1)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Tell the multiplexer the handler went away.
        harness.multiplexer.parentHandlerRemoved()

        // Issue a write to the child.
        var bytes = channel.allocator.buffer(capacity: 1024)
        bytes.writeString("Hello from the unit tests")
        XCTAssertThrowsError(try channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(bytes))).wait()) { error in
            XCTAssertEqual(error as? ChannelError, .ioOnClosedChannel)
        }

        XCTAssertEqual(harness.flushedMessages.count, 1)
    }

    func testMultiplexerRejectsInboundMessagesForUnknownChannels() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }

        // Activate the channel.
        XCTAssertEqual(harness.flushedMessages.count, 1)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Try to send a message to the next channel ID. This will be rejected.
        XCTAssertThrowsError(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID! &+ 1, peerChannelID: 2))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .some(.protocolViolation))
        }

        // Close the channel.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.close(peerChannelID: channelID!)))
        harness.eventLoop.run()

        // Sending a message to that channel is also rejected.
        XCTAssertThrowsError(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .some(.protocolViolation))
        }
    }

    func testCannotOpenNewChannelAfterDroppingDelegate() throws {
        let harness = self.harnessForbiddingInboundChannels()
        harness.finish()

        let promise = harness.eventLoop.makePromise(of: Channel.self)
        harness.multiplexer.createChildChannel(promise, channelType: .session, nil)

        XCTAssertThrowsError(try promise.futureResult.wait()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .some(.protocolViolation))
        }
    }

    func testEOFIsReceivedInOrder() throws {
        let readRecorder = ReadRecordingHandler()
        let eofRecorder = EOFRecorder()

        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        // We're going to deliver a series of data messages, which should not be processed until read is called.
        var buffer = harness.delegate._channel.allocator.buffer(capacity: 1024)
        buffer.writeString("Hello from the unit tests")

        // Let's create a channel.
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            channel.setOption(ChannelOptions.autoRead, value: false).flatMap {
                channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            }.flatMap {
                channel.pipeline.addHandlers([readRecorder, eofRecorder])
            }
        }

        XCTAssertEqual(harness.flushedMessages.count, 1)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))
        XCTAssertEqual(readRecorder.reads, [])

        // Now we're going to deliver some data. These should not propagate into the channel.
        for _ in 0 ..< 5 {
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!, data: buffer)))
        }

        // And we're going to deliver an EOF message as well. We require that this not be re-ordered with the reads.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))
        XCTAssertFalse(eofRecorder.seenEOF)

        // Issue a read. Everything fires through.
        readRecorder.channel?.read()
        XCTAssertEqual(readRecorder.reads, Array(repeating: .init(type: .channel, data: .byteBuffer(buffer)), count: 5))
        XCTAssertEqual(harness.flushedMessages.count, 1)
        XCTAssertTrue(eofRecorder.seenEOF)
    }

    func testEOFIsSentInOrder() throws {
        let inactiveRecorder = ChannelInactiveRecorder()
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.pipeline.addHandler(inactiveRecorder)
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Activate channel.
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))

        // Ok, we're going to write 5 data frames. We won't flush them: doing an outbound close _is_ a flush.
        var buffer = channel.allocator.buffer(capacity: 1024)
        buffer.writeString("Hello from the unit tests!")

        for _ in 0 ..< 5 {
            channel.write(SSHChannelData(type: .channel, data: .byteBuffer(buffer)), promise: nil)
        }

        // Now we're going to add a final write: this will have a write promise. It should complete before
        // the close promise does.
        var finalWriteComplete = false
        var eofComplete = false
        channel.write(SSHChannelData(type: .channel, data: .byteBuffer(buffer))).whenSuccess {
            XCTAssertFalse(eofComplete)
            XCTAssertFalse(inactiveRecorder.seenInactive)
            finalWriteComplete = true
        }

        // Nothing has been written yet.
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Ok, send EOF.
        channel.close(mode: .output).whenSuccess {
            XCTAssertTrue(finalWriteComplete)
            XCTAssertFalse(inactiveRecorder.seenInactive)
            eofComplete = true
        }

        // We should have seen 7 messages.
        XCTAssertEqual(harness.flushedMessages.count, 8)
        harness.flushedMessages.dropFirst().prefix(6).forEach { message in
            XCTAssertEqual(SSHMessage.channelData(.init(recipientChannel: 1, data: buffer)), message)
        }
        XCTAssertEqual(SSHMessage.channelEOF(.init(recipientChannel: 1)), harness.flushedMessages.last)

        XCTAssertTrue(finalWriteComplete)
        XCTAssertTrue(eofComplete)
    }

    func testWriteAfterEOFFails() throws {
        let readRecorder = ReadRecordingHandler()
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.pipeline.addHandler(readRecorder)
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Activate channel.
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))

        // Write EOF.
        XCTAssertNoThrow(try channel.close(mode: .output).wait())
        XCTAssertTrue(channel.isActive)

        // Now write some data. This fails immediately.
        XCTAssertThrowsError(try channel.write(SSHChannelData(type: .channel, data: .byteBuffer(channel.allocator.buffer(capacity: 1024)))).wait()) { error in
            XCTAssertEqual(error as? ChannelError, .outputClosed)
        }
    }

    func testDuplicateCloseFails() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Activate channel.
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))

        var first: Result<Void, Error>?
        var second: Result<Void, Error>?

        channel.close().whenComplete { result in first = result }
        channel.close().whenComplete { result in second = result }

        XCTAssertNil(first)
        XCTAssertNil(second)

        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.close(peerChannelID: channelID!)))

        guard case .success = first, case .success = second else {
            XCTFail("Unexpected results: first \(String(describing: first)) second \(String(describing: second))")
            return
        }

        XCTAssertThrowsError(try channel.close().wait()) { error in
            XCTAssertEqual(error as? ChannelError, .alreadyClosed)
        }
    }

    func testClosingInputRejected() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Activate channel.
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))

        XCTAssertThrowsError(try channel.close(mode: .input).wait()) { error in
            XCTAssertEqual(error as? ChannelError, .operationUnsupported)
        }
    }

    func testSimpleOutboundFlowControlManagement() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Activate channel. We set a 5 byte window size just to make testing easier.
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1, initialWindowSize: 5)))
        XCTAssertTrue(channel.isWritable)

        var buffer = channel.allocator.buffer(capacity: 6)
        buffer.writeBytes(0 ..< 6)

        // Ok, send 3 bytes of data. Nothing happens. However, when this completes writability will still be false.
        channel.write(SSHChannelData(type: .channel, data: .byteBuffer(buffer.getSlice(at: buffer.readerIndex, length: 3)!)), promise: nil)
        XCTAssertTrue(channel.isWritable)

        // Now write 2 bytes of stderr. This flips the writability to false.
        channel.write(SSHChannelData(type: .channel, data: .byteBuffer(buffer.getSlice(at: buffer.readerIndex, length: 2)!)), promise: nil)
        XCTAssertFalse(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Flush the writes. This does not change writability.
        channel.flush()
        XCTAssertFalse(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 3)

        // Another attempt at writing queues the write.
        channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buffer)), promise: nil)
        XCTAssertFalse(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 3)

        // Receiving a window increment dequeues an appropriate amount of the write.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.windowAdjust(peerChannelID: channelID!, increment: 1)))
        harness.multiplexer.parentChannelReadComplete()
        XCTAssertFalse(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 4)
        XCTAssertEqual(harness.flushedMessages.last, .channelData(.init(recipientChannel: 1, data: buffer.getSlice(at: buffer.readerIndex, length: 1)!)))

        // Same dance again just to confirm it keeps happening.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.windowAdjust(peerChannelID: channelID!, increment: 1)))
        harness.multiplexer.parentChannelReadComplete()
        XCTAssertFalse(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 5)
        XCTAssertEqual(harness.flushedMessages.last, .channelData(.init(recipientChannel: 1, data: buffer.getSlice(at: buffer.readerIndex + 1, length: 1)!)))

        // Now we grant way more window space. The channel becomes writable.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.windowAdjust(peerChannelID: channelID!, increment: 100)))
        harness.multiplexer.parentChannelReadComplete()
        XCTAssertTrue(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 6)
        XCTAssertEqual(harness.flushedMessages.last,
                       .channelData(.init(recipientChannel: 1, data: buffer.getSlice(at: buffer.readerIndex + 2, length: buffer.readableBytes - 2)!)))
    }

    func testWeCorrectlySpotWindowSizesOfInboundChannels() throws {
        var childChannel: Channel?

        let harness = self.harness { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }
        defer {
            harness.finish()
        }

        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openRequest(channelID: 1, initialWindowSize: 5)))

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        var buffer = channel.allocator.buffer(capacity: 5)
        buffer.writeBytes(0 ..< 5)

        // Ok, we're gonna write the first 4 bytes. The channel will stay writable.
        XCTAssertTrue(channel.isWritable)
        channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buffer.getSlice(at: buffer.readerIndex, length: 4)!)), promise: nil)
        XCTAssertTrue(channel.isWritable)

        // The next byte makes the channel not writable.
        channel.write(SSHChannelData(type: .channel, data: .byteBuffer(buffer.getSlice(at: buffer.readerIndex, length: 1)!)), promise: nil)
        XCTAssertFalse(channel.isWritable)
    }

    func testWeRejectExcessiveWindowSizes() throws {
        var childChannel: Channel?

        let harness = self.harness { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }
        defer {
            harness.finish()
        }

        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openRequest(channelID: 1, initialWindowSize: 5)))

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        let channelID = self.assertChannelOpenConfirmation(harness.flushedMessages.first, recipientChannel: 1)
        XCTAssertTrue(channel.isActive)

        // Now we set enough to overflow the window.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.windowAdjust(peerChannelID: channelID!, increment: UInt32.max - 4)))

        // The channel should have been closed.
        XCTAssertFalse(channel.isActive)
        self.assertChannelClose(harness.flushedMessages.last, recipientChannel: 1)
    }

    func testWeDealWithFlowControlProperly() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.setOption(ChannelOptions.autoRead, value: false)
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Activate channel.
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))

        // The default window size is 1<<24 bytes. Sadly, we need a buffer that size.
        // Sorry for the unsafe code, but otherwise this test takes _ages_.
        var buffer = channel.allocator.buffer(capacity: (1 << 24) + 1)
        buffer.writeWithUnsafeMutableBytes(minimumWritableBytes: (1 << 24) + 1) { ptr in
            memset(ptr.baseAddress!, 0, (1 << 24) + 1)
            return (1 << 24) + 1
        }

        // We're going to write one byte short.
        XCTAssertEqual(harness.flushedMessages.count, 1)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!,
                                                                          data: buffer.getSlice(at: buffer.readerIndex, length: (1 << 23) - 1)!)))

        // Auto read is off, so nothing happens.
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Issue a read. This isn't half the buffer size, so nothing happens.
        channel.read()
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Send a 1-byte data message. Again, there's no autoread, so this does nothing.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!,
                                                                          data: buffer.getSlice(at: buffer.readerIndex, length: 1)!)))
        XCTAssertEqual(harness.flushedMessages.count, 1)

        // Now issue a read. This triggers an outbound message.
        channel.read()
        XCTAssertEqual(harness.flushedMessages.count, 2)
        self.assertWindowAdjust(harness.flushedMessages.last, recipientChannel: 1, delta: 1 << 23)

        // Now issue a really big read. Again, there's no autoread, so this does nothing.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!,
                                                                          data: buffer.getSlice(at: buffer.readerIndex, length: 1 << 24)!)))
        XCTAssertEqual(harness.flushedMessages.count, 2)

        // Issue the read. A new outbound message with a bigger window increment.
        channel.read()
        XCTAssertEqual(harness.flushedMessages.count, 3)
        self.assertWindowAdjust(harness.flushedMessages.last, recipientChannel: 1, delta: 1 << 24)

        // Finally, issue an excessively large read. This should cause an error.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!, data: buffer)))
        XCTAssertEqual(harness.flushedMessages.count, 4)
        self.assertChannelClose(harness.flushedMessages.last, recipientChannel: 1)
    }

    func testRespectingMaxMessageSize() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        var childChannel: Channel?
        harness.multiplexer.createChildChannel(channelType: .session) { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        // Activate channel. We set a 5 byte window size just to make testing easier.
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1, initialWindowSize: 5, maxPacketSize: 3)))
        XCTAssertTrue(channel.isWritable)

        var buffer = channel.allocator.buffer(capacity: 6)
        buffer.writeBytes(0 ..< 6)

        // Ok, send 6 bytes of data immediately. The writability is false.
        channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buffer)), promise: nil)
        XCTAssertFalse(channel.isWritable)

        // Two writes should have occurred, one of size 3 and one of size 2.
        XCTAssertEqual(harness.flushedMessages.count, 3)
        self.assertChannelData(harness.flushedMessage(1), data: buffer.getSlice(at: buffer.readerIndex, length: 3)!, recipientChannel: 1)
        self.assertChannelData(harness.flushedMessage(2), data: buffer.getSlice(at: buffer.readerIndex + 3, length: 2)!, recipientChannel: 1)

        // Flush the writes. Nothing changes
        channel.flush()
        XCTAssertFalse(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 3)

        // Issue another write, now of extended data, which is also bound by this limit. Again, nothing changes.
        channel.writeAndFlush(SSHChannelData(type: .stdErr, data: .byteBuffer(buffer)), promise: nil)
        XCTAssertFalse(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 3)

        // Now hand back some window size. We'll say...5 bytes.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.windowAdjust(peerChannelID: channelID!, increment: 5)))
        harness.multiplexer.parentChannelReadComplete()

        // This issues three more writes: the remaining 1 byte of regular data, 3 bytes of extra data, and 1 byte of extra data.
        XCTAssertFalse(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 6)
        self.assertChannelData(harness.flushedMessage(3), data: buffer.getSlice(at: buffer.readerIndex + 5, length: 1)!, recipientChannel: 1)
        self.assertChannelExtendedData(harness.flushedMessage(4), type: .stderr, data: buffer.getSlice(at: buffer.readerIndex, length: 3)!, recipientChannel: 1)
        self.assertChannelExtendedData(harness.flushedMessage(5), type: .stderr, data: buffer.getSlice(at: buffer.readerIndex + 3, length: 1)!, recipientChannel: 1)

        // Now we hand back another 5 bytes of data, which allows everything else through.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.windowAdjust(peerChannelID: channelID!, increment: 5)))
        harness.multiplexer.parentChannelReadComplete()
        XCTAssertTrue(channel.isWritable)
        XCTAssertEqual(harness.flushedMessages.count, 7)
        self.assertChannelExtendedData(harness.flushedMessage(6), type: .stderr, data: buffer.getSlice(at: buffer.readerIndex + 4, length: 2)!, recipientChannel: 1)
    }

    func testRespectingMaxMessageSizeOnOutboundChannel() throws {
        var childChannel: Channel?

        let harness = self.harness { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }
        defer {
            harness.finish()
        }

        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openRequest(channelID: 1, initialWindowSize: 5, maxPacketSize: 3)))

        guard let channel = childChannel else {
            XCTFail("Did not create child channel")
            return
        }

        var buffer = channel.allocator.buffer(capacity: 5)
        buffer.writeBytes(0 ..< 5)

        // Ok, we're gonna write 5 bytes. These will be split into two writes.
        channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buffer)), promise: nil)
        XCTAssertEqual(harness.flushedMessages.count, 3)
        self.assertChannelData(harness.flushedMessage(1), data: buffer.getSlice(at: buffer.readerIndex, length: 3)!, recipientChannel: 1)
        self.assertChannelData(harness.flushedMessage(2), data: buffer.getSlice(at: buffer.readerIndex + 3, length: 2)!, recipientChannel: 1)
    }

    func testPromiseCompletionDelaysUntilResponse() {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        var childPromiseComplete = false
        let childPromise: EventLoopPromise<Channel> = harness.eventLoop.makePromise()
        childPromise.futureResult.whenSuccess { _ in childPromiseComplete = true }
        harness.multiplexer.createChildChannel(childPromise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }

        XCTAssertFalse(childPromiseComplete)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)

        // Now we drop in an open confirmation. The promise completes.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openConfirmation(originalChannelID: channelID!, peerChannelID: 1)))
        XCTAssertTrue(childPromiseComplete)
    }

    func testPromiseCompletionDelaysUntilResponseOnFailure() {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        var childPromiseError: Error?
        let childPromise: EventLoopPromise<Channel> = harness.eventLoop.makePromise()
        childPromise.futureResult.whenFailure { error in childPromiseError = error }
        harness.multiplexer.createChildChannel(childPromise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }

        XCTAssertNil(childPromiseError)
        let channelID = self.assertChannelOpen(harness.flushedMessages.first)

        // Now we drop in an open failure. The promise completes.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openFailure(originalChannelID: channelID!, reasonCode: 1)))
        XCTAssertEqual((childPromiseError as? NIOSSHError?)??.type, .channelSetupRejected)
    }

    func testTCPCloseWhileAwaitingChannelSetup() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        var childPromiseError: Error?
        let childPromise: EventLoopPromise<Channel> = harness.eventLoop.makePromise()
        var childChannel: Channel?
        childPromise.futureResult.whenFailure { error in childPromiseError = error }

        harness.multiplexer.createChildChannel(childPromise, channelType: .session) { channel, _ in
            childChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = childChannel else {
            XCTFail("Did not create channnel")
            return
        }
        XCTAssertNil(childPromiseError)
        XCTAssertFalse(channel.isActive)
        self.assertChannelOpen(harness.flushedMessages.first)

        // Now we drop in a TCP closure. The promise completes and the channel stays inactive, but is now closed.
        harness.multiplexer.parentChannelInactive()
        XCTAssertEqual((childPromiseError as? NIOSSHError?)??.type, .tcpShutdown)

        harness.eventLoop.run()
        XCTAssertThrowsError(try channel.closeFuture.wait()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .tcpShutdown)
        }
    }

    func testTCPCloseWhileAwaitingInitializer() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)
        let childPromise: EventLoopPromise<Channel> = harness.eventLoop.makePromise()
        let delayPromise = harness.eventLoop.makePromise(of: Void.self)

        var childPromiseError: Error?
        childPromise.futureResult.whenFailure { error in childPromiseError = error }

        harness.multiplexer.createChildChannel(childPromise, channelType: .session) { _, _ in
            delayPromise.futureResult
        }

        XCTAssertEqual(harness.flushedMessages.count, 0)

        // Now we drop in a TCP closure. The promise stays incomplete.
        harness.multiplexer.parentChannelInactive()
        harness.eventLoop.run()
        XCTAssertNil(childPromiseError)

        // Now complete the delay promise.
        delayPromise.succeed(())
        XCTAssertEqual((childPromiseError as? NIOSSHError?)??.type, .tcpShutdown)
    }

    func testErrorGracePeriod() throws {
        let harness = self.harness { channel, _ in
            channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
        }
        defer {
            harness.finish()
        }

        let openRequest = self.openRequest(channelID: 1)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(openRequest))
        let channelID = self.assertChannelOpenConfirmation(harness.flushedMessages.first, recipientChannel: 1)

        // Ok, we're going to force the channel to encounter an error. We can do that by violating the state machine rules:
        // we'll send EOF twice.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))

        harness.eventLoop.run()

        // Ok, we should see one message, close.
        self.assertChannelClose(harness.flushedMessage(1), recipientChannel: 1)

        // Now, we're going to fire in another few messages. These messages are gibberish, but they'll be allowed. The child channel is
        // gone, and so it's no longer enforcing its state machine.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))

        // Now we're going to send a close. This will be accepted as well.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.close(peerChannelID: channelID!)))

        // But now further frames are rejected.
        XCTAssertThrowsError(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testLocalChildChannelsAlwaysGetTheRightChannelType() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        var initializedChannels = [SSHChannelType]()
        var typesFromOptions = [SSHChannelType]()

        let channelTypes = [
            SSHChannelType.session,
            SSHChannelType.directTCPIP(.init(targetHost: "apple.com", targetPort: 443, originatorAddress: try! .init(ipAddress: "127.0.0.1", port: 8765))),
            SSHChannelType.forwardedTCPIP(.init(listeningHost: "localhost", listeningPort: 80, originatorAddress: try! .init(ipAddress: "fe80::1", port: 70))),
        ]

        for channelType in channelTypes {
            harness.multiplexer.createChildChannel(channelType: channelType) { channel, type in
                initializedChannels.append(type)

                return channel.getOption(SSHChildChannelOptions.sshChannelType).map { type in
                    typesFromOptions.append(type)
                }
            }
        }

        XCTAssertEqual(initializedChannels, channelTypes)
    }

    func testRemotelyCreatedChildChannelsGetTheRightChannelType() throws {
        var initializedChannels = [SSHChannelType]()
        var typesFromOptions = [SSHChannelType]()

        let harness = self.harness { channel, type in
            initializedChannels.append(type)

            return channel.getOption(SSHChildChannelOptions.sshChannelType).map { type in
                typesFromOptions.append(type)
            }
        }

        let channelTypes = [
            SSHChannelType.session,
            SSHChannelType.directTCPIP(.init(targetHost: "apple.com", targetPort: 443, originatorAddress: try! .init(ipAddress: "127.0.0.1", port: 8765))),
            SSHChannelType.forwardedTCPIP(.init(listeningHost: "localhost", listeningPort: 80, originatorAddress: try! .init(ipAddress: "fe80::1", port: 70))),
        ]

        for (channelID, channelType) in channelTypes.enumerated() {
            let message = SSHMessage.channelOpen(.init(type: .init(channelType), senderChannel: UInt32(channelID), initialWindowSize: 1 << 24, maximumPacketSize: 1 << 24))
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(message))
        }

        XCTAssertEqual(initializedChannels, channelTypes)
    }

    func testAutoReadOnChildChannel() throws {
        let readCounter = ReadCountingHandler()

        let harness = self.harness { channel, _ in
            channel.pipeline.addHandler(readCounter)
        }
        defer {
            harness.finish()
        }

        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openRequest(channelID: 1)))
        let channelID = self.assertChannelOpenConfirmation(harness.flushedMessages.first, recipientChannel: 1)
        XCTAssertEqual(readCounter.readCount, 1)

        // Now we're going to deliver some data. These should not propagate into the channel until channelReadComplete.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeString("hello, world!")

        for _ in 0 ..< 5 {
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!, data: buffer)))
        }
        XCTAssertEqual(readCounter.readCount, 1)

        harness.multiplexer.parentChannelReadComplete()
        XCTAssertEqual(readCounter.readCount, 2)

        // If no reads were delivered, further channel read completes do not trigger read() calls.
        harness.multiplexer.parentChannelReadComplete()
        XCTAssertEqual(readCounter.readCount, 2)
    }

    func testTCPCloseBeforeInitializer() throws {
        let harness = self.harnessForbiddingInboundChannels()
        defer {
            harness.finish()
        }

        let childPromise: EventLoopPromise<Channel> = harness.eventLoop.makePromise()

        var childPromiseError: Error?
        childPromise.futureResult.whenFailure { error in childPromiseError = error }

        // TCP Close
        harness.multiplexer.parentChannelInactive()
        harness.multiplexer.createChildChannel(childPromise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        harness.eventLoop.run()

        XCTAssertEqual(harness.flushedMessages.count, 0)
        XCTAssertEqual((childPromiseError as? NIOSSHError?)??.type, .tcpShutdown)
    }

    func testEOFQueuesWithReads() throws {
        let eofHandler = EOFRecorder()
        let readRecorder = ReadRecordingHandler()

        let harness = self.harness { channel, _ in
            channel.setOption(ChannelOptions.autoRead, value: true).flatMap {
                channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            }.flatMap {
                channel.pipeline.addHandlers([readRecorder, eofHandler])
            }
        }
        defer {
            harness.finish()
        }

        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openRequest(channelID: 1)))
        let channelID = self.assertChannelOpenConfirmation(harness.flushedMessages.first, recipientChannel: 1)
        XCTAssertEqual(readRecorder.reads.count, 0)
        XCTAssertFalse(eofHandler.seenEOF)

        // Now we're going to deliver some data, followed by EOF. We should not see either until channelReadComplete.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeString("hello, world!")

        for _ in 0 ..< 5 {
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!, data: buffer)))
        }
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))
        XCTAssertEqual(readRecorder.reads.count, 0)
        XCTAssertFalse(eofHandler.seenEOF)

        harness.multiplexer.parentChannelReadComplete()
        XCTAssertEqual(readRecorder.reads.count, 5)
        XCTAssertTrue(eofHandler.seenEOF)
    }

    func testNoDataLossOnChannelClose() throws {
        let eofHandler = EOFRecorder()
        let readRecorder = ReadRecordingHandler()

        let harness = self.harness { channel, _ in
            channel.setOption(ChannelOptions.autoRead, value: true).flatMap {
                channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            }.flatMap {
                channel.pipeline.addHandlers([readRecorder, eofHandler])
            }
        }
        defer {
            harness.finish()
        }

        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.openRequest(channelID: 1)))
        let channelID = self.assertChannelOpenConfirmation(harness.flushedMessages.first, recipientChannel: 1)
        XCTAssertEqual(readRecorder.reads.count, 0)
        XCTAssertFalse(eofHandler.seenEOF)

        // Now we're going to deliver some data, followed by EOF. We should not see either until channelReadComplete.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeString("hello, world!")

        for _ in 0 ..< 5 {
            XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.data(peerChannelID: channelID!, data: buffer)))
        }
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.eof(peerChannelID: channelID!)))
        XCTAssertEqual(readRecorder.reads.count, 0)
        XCTAssertFalse(eofHandler.seenEOF)

        // Now we'll deliver channel close. This will force the channel closed, but we _must_ not lose the data.
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(self.close(peerChannelID: channelID!)))
        XCTAssertEqual(readRecorder.reads.count, 5)
        XCTAssertTrue(eofHandler.seenEOF)
    }

    func testChildChannelSupportsSyncOptions() throws {
        var createdChannels = 0
        let harness = self.harness { channel, _ in
            createdChannels += 1

            guard let sync = channel.syncOptions else {
                XCTFail("\(channel) does not support syncOptions but should")
                return channel.eventLoop.makeSucceededFuture(())
            }

            do {
                let autoRead = try sync.getOption(ChannelOptions.autoRead)
                try sync.setOption(ChannelOptions.autoRead, value: !autoRead)
                XCTAssertNotEqual(try sync.getOption(ChannelOptions.autoRead), autoRead)
            } catch {
                XCTFail("Unable to get/set autoRead using synchronous options")
            }

            return channel.eventLoop.makeSucceededFuture(())
        }
        defer {
            harness.finish()
        }

        XCTAssertEqual(createdChannels, 0)
        XCTAssertEqual(harness.flushedMessages.count, 0)

        let openRequest = self.openRequest(channelID: 1)
        XCTAssertNoThrow(try harness.multiplexer.receiveMessage(openRequest))
        XCTAssertEqual(createdChannels, 1)
        XCTAssertEqual(harness.flushedMessages.count, 1)
        XCTAssertNil(harness.delegate.writes.first?.1)

        self.assertChannelOpenConfirmation(harness.flushedMessages.first, recipientChannel: 1)
    }
}
