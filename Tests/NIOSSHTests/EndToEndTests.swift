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
@testable import NIOSSH
import XCTest

enum EndToEndTestError: Error {
    case unableToCreateChildChannel, invalidCustomPublicKey, invalidCustomSignature
}

fileprivate let testKey = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])

final class CustomTransportProtection: NIOSSHTransportProtection {
    static let cipherName = "xor-with-42"
    static let macName: String? = "insecure-sha1"
    static var wasUsed = false
    
    static var keySizes: ExpectedKeySizes {
        .init(ivSize: 19, encryptionKeySize: 17, macKeySize: 15)
    }
    
    required init(initialKeys: NIOSSHSessionKeys) throws {}
    
    static var cipherBlockSize: Int { 18 }
    var macBytes: Int { 20 }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {}

    func decryptFirstBlock(_: inout ByteBuffer) throws {
        // For us, decrypting the first block is very easy: do nothing. The length bytes are already
        // unencrypted!
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        Self.wasUsed = true
        var plaintext: Data

        // The first 4 bytes are the length. The last 16 are the tag. Everything else is ciphertext. We expect
        // that the ciphertext is a clean multiple of the block size, and to be non-zero.
        guard
            let lengthView: UInt32 = source.readInteger(),
            var ciphertext = source.readData(length: Int(lengthView)),
            let mac = source.readData(length: Insecure.SHA1.byteCount),
              ciphertext.count > 0, ciphertext.count % Self.cipherBlockSize == 0 else {
            // The only way this fails is if the payload doesn't match this encryption scheme.
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        for i in 0..<ciphertext.count {
            ciphertext[i] ^= 42
        }
        
        plaintext = ciphertext
        
        struct InvalidSHA1TestSignature: Error {}
        guard Insecure.SHA1.hash(data: plaintext) == mac else {
            throw InvalidSHA1TestSignature()
        }
        
        let paddingBytes = plaintext[0]
        
        if paddingBytes < 4 || paddingBytes >= plaintext.count {
            throw NIOSSHError.invalidDecryptedPlaintextLength
        }
        
        // All good! A quick soundness check to verify that the length of the plaintext is ok.
        guard plaintext.count % Self.cipherBlockSize == 0, plaintext.count == ciphertext.count else {
            throw NIOSSHError.invalidDecryptedPlaintextLength
        }
        
        // Remove padding
        plaintext.removeFirst()
        plaintext.removeLast(Int(paddingBytes))
        
        return ByteBuffer(data: plaintext)
    }

    func encryptPacket(_ packet: NIOSSHEncryptablePayload, to outboundBuffer: inout ByteBuffer, sequenceNumber: UInt32) throws {
        // Keep track of where the length is going to be written.
        let packetLengthIndex = outboundBuffer.writerIndex
        let packetLengthLength = MemoryLayout<UInt32>.size
        let packetPaddingIndex = outboundBuffer.writerIndex + packetLengthLength
        let packetPaddingLength = MemoryLayout<UInt8>.size

        outboundBuffer.moveWriterIndex(forwardBy: packetLengthLength + packetPaddingLength)

        // First, we write the packet.
        let payloadBytes = outboundBuffer.writeEncryptablePayload(packet)

        // Ok, now we need to pad. The rules for padding for AES GCM are:
        //
        // 1. We must pad out such that the total encrypted content (padding length byte,
        //     plus content bytes, plus padding bytes) is a multiple of the block size.
        // 2. At least 4 bytes of padding MUST be added.
        // 3. This padding SHOULD be random.
        //
        // Note that, unlike other protection modes, the length is not encrypted, and so we
        // must exclude it from the padding calculation.
        //
        // So we check how many bytes we've already written, use modular arithmetic to work out
        // how many more bytes we need, and then if that's fewer than 4 we add a block size to it
        // to fill it out.
        var encryptedBufferSize = payloadBytes + packetPaddingLength
        var necessaryPaddingBytes = Self.cipherBlockSize - (encryptedBufferSize % Self.cipherBlockSize)
        if necessaryPaddingBytes < 4 {
            necessaryPaddingBytes += Self.cipherBlockSize
        }

        // We now want to write that many padding bytes to the end of the buffer. These are supposed to be
        // random bytes. We're going to get those from the system random number generator.
        encryptedBufferSize += outboundBuffer.writeSSHPaddingBytes(count: necessaryPaddingBytes)
        precondition(encryptedBufferSize % Self.cipherBlockSize == 0, "Incorrectly counted buffer size; got \(encryptedBufferSize)")

        // We now know the length: it's going to be "encrypted buffer size". The length does not include the tag, so don't add it.
        // Let's write that in. We also need to write the number of padding bytes in.
        outboundBuffer.setInteger(UInt32(encryptedBufferSize), at: packetLengthIndex)
        outboundBuffer.setInteger(UInt8(necessaryPaddingBytes), at: packetPaddingIndex)

        // Ok, nice! Now we need to encrypt the data. We pass the length field as additional authenticated data, and the encrypted
        // payload portion as the data to encrypt. We know these views will be valid, so we forcibly unwrap them: if they're invalid,
        // our math was wrong and we cannot recover.
        let plaintext = outboundBuffer.getBytes(at: packetPaddingIndex, length: encryptedBufferSize)!
        let hash = Insecure.SHA1.hash(data: plaintext)
                                      
        var ciphertext = plaintext
        for i in 0..<ciphertext.count {
            ciphertext[i] ^= 42
        }

        // We now want to overwrite the portion of the bytebuffer that contains the plaintext with the ciphertext, and then append the
        // tag.
        outboundBuffer.setContiguousBytes(ciphertext, at: packetPaddingIndex)
        let macLength = outboundBuffer.writeBytes(hash)
        precondition(macLength == self.macBytes, "Unexpected short tag")
    }
}

struct CustomPrivateKey: NIOSSHPrivateKeyProtocol {
    static let keyPrefix = "custom-prefix"
    
    var publicKey: NIOSSHPublicKeyProtocol {
        CustomPublicKey()
    }
    
    func generatedSharedSecret(with theirKey: CustomPublicKey) throws -> [UInt8] {
        return Array(testKey.reversed())
    }
    
    func signature<D>(for data: D) throws -> NIOSSHSignatureProtocol where D : DataProtocol {
        var data = Data(data)
        
        let testKeySize = testKey.count
        for i in 0..<data.count {
            data[i] ^= testKey[i % testKeySize]
        }
        
        return CustomSignature(rawRepresentation: data)
    }
}

struct CustomSignature: NIOSSHSignatureProtocol {
    static let signaturePrefix = "custom-prefix"
    
    let rawRepresentation: Data
    
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(rawRepresentation)
    }
    
    static func read(from buffer: inout ByteBuffer) throws -> CustomSignature {
        guard var buffer = buffer.readSSHString() else {
            throw EndToEndTestError.invalidCustomSignature
        }
        
        let data = buffer.readData(length: buffer.readableBytes)!
        return CustomSignature(rawRepresentation: data)
    }
}

struct CustomPublicKey: NIOSSHPublicKeyProtocol {
    static let publicKeyPrefix = "custom-prefix"
    static let keyExchangeAlgorithmNames: [Substring] = ["custom-handshake"]
    static var wasUsed = false
    
    func isValidSignature<D>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool where D : DataProtocol {
        let testKeySize = testKey.count
        var data = Data(data)
        for i in 0..<data.count {
            data[i] ^= testKey[i % testKeySize]
        }
        
        return data == signature.rawRepresentation
    }
    
    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        return 0
    }
    
    var rawRepresentation: Data {
        testKey
    }
    
    static func read(from buffer: inout ByteBuffer) throws -> CustomPublicKey {
        guard buffer.readableBytes == 0 else {
            throw EndToEndTestError.invalidCustomPublicKey
        }
        
        wasUsed = true
        return CustomPublicKey()
    }
}

struct CustomKeyExchange: NIOSSHKeyExchangeAlgorithmProtocol {
    static var keyExchangeInitMessageId: UInt8 { 0xff }
    static var keyExchangeReplyMessageId: UInt8 { 0xff }
    static var wasUsed = false
    
    private var previousSessionIdentifier: ByteBuffer?
    private var ourKey: CustomPrivateKey
    private var theirKey: CustomPublicKey?
    private var ourRole: SSHConnectionRole
    private var sharedSecret: [UInt8]?
    
    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.ourKey = CustomPrivateKey()
        self.previousSessionIdentifier = previousSessionIdentifier
    }

    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> ByteBuffer {
        var buffer = ByteBuffer()
        _ = ourKey.publicKey.write(to: &buffer)
        return buffer
    }

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: ByteBuffer,
        serverHostKey: NIOSSHPrivateKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, NIOSSHKeyExchangeServerReply) {
        var theirKeyBuffer = message
        let theirKey = try CustomPublicKey.read(from: &theirKeyBuffer)
        self.theirKey = theirKey
        
        // Shared secet is "expanded"
        // That should make it usable by most transport encryption, at least the one used in our test
        var sharedSecret = try self.ourKey.generatedSharedSecret(with: theirKey)
        sharedSecret += sharedSecret
        sharedSecret += sharedSecret
        sharedSecret += sharedSecret
        sharedSecret += sharedSecret
        
        self.sharedSecret = sharedSecret
        
        var hasher = SHA512()
        hasher.update(data: initialExchangeBytes.readableBytesView)
        hasher.update(data: sharedSecret)
        
        let exchangeHash = hasher.finalize()
        
        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            sessionID = ByteBuffer(bytes: SHA512.hash(data: Data(exchangeHash)))
        }
        
        let kexResult = KeyExchangeResult(
            sessionID: sessionID,
            keys: NIOSSHSessionKeys(
                initialInboundIV: Array(sharedSecret[0..<expectedKeySizes.ivSize]),
                initialOutboundIV: Array(sharedSecret[0..<expectedKeySizes.ivSize]),
                inboundEncryptionKey: SymmetricKey(data: Data(sharedSecret[0..<expectedKeySizes.encryptionKeySize])),
                outboundEncryptionKey: SymmetricKey(data: Data(sharedSecret[0..<expectedKeySizes.encryptionKeySize])),
                inboundMACKey: SymmetricKey(data: Data(sharedSecret[0..<expectedKeySizes.macKeySize])),
                outboundMACKey: SymmetricKey(data: Data(sharedSecret[0..<expectedKeySizes.macKeySize]))
            )
        )
        
        var publicKeyBytes = allocator.buffer(capacity: 256)
        _ = self.ourKey.publicKey.write(to: &publicKeyBytes)
        
        let exchangeHashSignature = try serverHostKey.sign(digest: exchangeHash)
        
        let serverReply = NIOSSHKeyExchangeServerReply(hostKey: serverHostKey.publicKey,
                                                       publicKey: publicKeyBytes, signature: exchangeHashSignature)
       
        Self.wasUsed = true
        return (kexResult, serverReply)
    }

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage: NIOSSHKeyExchangeServerReply,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult {
        var theirKeyBuffer = serverKeyExchangeMessage.publicKey
        let theirKey = try CustomPublicKey.read(from: &theirKeyBuffer)
        self.theirKey = theirKey
        
        // Shared secet is "expanded"
        // That should make it usable by most transport encryption, at least the one used in our test
        var sharedSecret = try self.ourKey.generatedSharedSecret(with: theirKey)
        sharedSecret += sharedSecret
        sharedSecret += sharedSecret
        sharedSecret += sharedSecret
        sharedSecret += sharedSecret
        self.sharedSecret = sharedSecret
        
        var hasher = SHA512()
        hasher.update(data: initialExchangeBytes.readableBytesView)
        hasher.update(data: sharedSecret)
        let exchangeHash = hasher.finalize()
        
        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            sessionID = ByteBuffer(bytes: SHA512.hash(data: Data(exchangeHash)))
        }
        
        guard serverKeyExchangeMessage.hostKey.isValidSignature(serverKeyExchangeMessage.signature, for: exchangeHash) else {
            throw NIOSSHError.invalidExchangeHashSignature
        }
        
        Self.wasUsed = true
        return KeyExchangeResult(
            sessionID: sessionID,
            keys: NIOSSHSessionKeys(
                initialInboundIV: Array(sharedSecret[0..<expectedKeySizes.ivSize]),
                initialOutboundIV: Array(sharedSecret[0..<expectedKeySizes.ivSize]),
                inboundEncryptionKey: SymmetricKey(data: Data(sharedSecret[0..<expectedKeySizes.encryptionKeySize])),
                outboundEncryptionKey: SymmetricKey(data: Data(sharedSecret[0..<expectedKeySizes.encryptionKeySize])),
                inboundMACKey: SymmetricKey(data: Data(sharedSecret[0..<expectedKeySizes.macKeySize])),
                outboundMACKey: SymmetricKey(data: Data(sharedSecret[0..<expectedKeySizes.macKeySize]))
            )
        )
    }

    static var keyExchangeAlgorithmNames: [Substring] { ["xorkex"] }
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

    func advanceTime(by increment: TimeAmount) {
        self.loop.advanceTime(by: increment)
    }

    func activate() throws {
        // A weird wrinkle of embedded channel is that it only properly activates on connect.
        try self.client.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
        try self.server.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
    }

    func configureWithHarness(_ harness: TestHarness) throws {
        var clientConfiguration = SSHClientConfiguration(userAuthDelegate: harness.clientAuthDelegate, serverAuthDelegate: harness.clientServerAuthDelegate, globalRequestDelegate: harness.clientGlobalRequestDelegate)
        var serverConfiguration = SSHServerConfiguration(hostKeys: harness.serverHostKeys, userAuthDelegate: harness.serverAuthDelegate, globalRequestDelegate: harness.serverGlobalRequestDelegate, banner: harness.serverAuthBanner)
        
        if let transportProtectionAlgoritms = harness.transportProtectionAlgoritms {
            clientConfiguration.transportProtectionSchemes = transportProtectionAlgoritms
            serverConfiguration.transportProtectionSchemes = transportProtectionAlgoritms
        }
        
        if let keyExchangeAlgorithms = harness.keyExchangeAlgorithms {
            clientConfiguration.keyExchangeAlgorithms = keyExchangeAlgorithms
            serverConfiguration.keyExchangeAlgorithms = keyExchangeAlgorithms
        }
        
        let clientHandler = NIOSSHHandler(role: .client(clientConfiguration),
                                          allocator: self.client.allocator,
                                          inboundChildChannelInitializer: nil)
        let serverHandler = NIOSSHHandler(role: .server(serverConfiguration),
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

    var clientServerAuthDelegate: NIOSSHClientServerAuthenticationDelegate = AcceptAllHostKeysDelegate()

    var clientGlobalRequestDelegate: GlobalRequestDelegate?

    var serverAuthDelegate: NIOSSHServerUserAuthenticationDelegate = DenyThenAcceptDelegate(messagesToDeny: 0)

    var serverGlobalRequestDelegate: GlobalRequestDelegate?

    var serverHostKeys: [NIOSSHPrivateKey] = [.init(ed25519Key: .init())]
    
    var keyExchangeAlgorithms: [NIOSSHKeyExchangeAlgorithmProtocol.Type]?

    var transportProtectionAlgoritms: [NIOSSHTransportProtection.Type]?
    
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

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        guard availableMethods.contains(.publicKey), let key = self.key else {
            nextChallengePromise.succeed(nil)
            return
        }

        self.key = nil
        nextChallengePromise.succeed(.init(username: "foo", serviceName: "ssh-connection", offer: .privateKey(.init(privateKey: key))))
    }
}

final class ExpectPublicKeyAuth: NIOSSHServerUserAuthenticationDelegate {
    private var key: NIOSSHPublicKey

    init(_ key: NIOSSHPublicKey) {
        self.key = key
    }

    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .publicKey

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
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

            func tcpForwardingRequest(_ request: GlobalRequest.TCPForwardingRequest, handler: NIOSSHHandler, promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>) {
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

        XCTAssertEqual(customDelegate.requests, [.listen(host: "localhost", port: 8765), .cancel(host: "localhost", port: 8765)])
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
            .init(wantReply: true, type: .unknown("test", randomPayload)), promise: firstReply
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertThrowsError(try firstReply.futureResult.wait())

        let secondReply = self.channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        clientSSHHandler.sendGlobalRequestMessage(
            .init(wantReply: false, type: .unknown("test", randomPayload)), promise: secondReply
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertNil(try secondReply.futureResult.wait())
    }

    func testGlobalRequestTooEarlyIsDelayed() throws {
        var completed = false
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
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
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err = error }
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(.listen(host: "localhost", port: 1234), promise: promise)
        XCTAssertNil(err)

        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(err as? ChannelError, .eof)
    }

    func testNeverStartedGlobalRequestsAreCancelledIfRemoved() throws {
        var err: Error?
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
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
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err = error }
        handler?.sendTCPForwardingRequest(.listen(host: "localhost", port: 1234), promise: promise)
        XCTAssertEqual(err as? ChannelError, .ioOnClosedChannel)
    }

    func testSecureEnclaveKeys() throws {
        // This is a quick end-to-end test that validates that we support secure enclave private keys
        // on appropriate platforms.
        #if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
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
    
    func testCustomPublicKeyAlgorithms() throws {
        NIOSSHAlgorithms.unregisterAlgorithms()
        CustomPublicKey.wasUsed = false
        NIOSSHAlgorithms.register(publicKey: CustomPublicKey.self, signature: CustomSignature.self)
        
        // If we can't create this key, we skip the test.
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let clientAuthKey = NIOSSHPrivateKey(custom: CustomPrivateKey())

        // We use the Secure Enclave keys for everything, just because we can.
        var harness = TestHarness()
        harness.serverHostKeys = [hostKey]
        harness.clientAuthDelegate = PrivateKeyClientAuth(clientAuthKey)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(clientAuthKey.publicKey)

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel, again, just because we can.
        _ = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
        XCTAssertTrue(CustomPublicKey.wasUsed)
    }
    
    func testCustomHostKeyAlgorithms() throws {
        NIOSSHAlgorithms.unregisterAlgorithms()
        CustomPublicKey.wasUsed = false
        NIOSSHAlgorithms.register(publicKey: CustomPublicKey.self, signature: CustomSignature.self)
        
        // If we can't create this key, we skip the test.
        let hostKey = NIOSSHPrivateKey(custom: CustomPrivateKey())
        let clientAuthKey = NIOSSHPrivateKey(ed25519Key: .init())

        // We use the Secure Enclave keys for everything, just because we can.
        var harness = TestHarness()
        harness.serverHostKeys = [hostKey]
        harness.clientAuthDelegate = PrivateKeyClientAuth(clientAuthKey)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(clientAuthKey.publicKey)

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel, again, just because we can.
        _ = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
        XCTAssertTrue(CustomPublicKey.wasUsed)
    }
    
    func testCustomTransportProtectionAlgorithms() throws {
        NIOSSHAlgorithms.unregisterAlgorithms()
        CustomKeyExchange.wasUsed = false
        NIOSSHAlgorithms.register(transportProtectionScheme: CustomTransportProtection.self)
        
        // If we can't create this key, we skip the test.
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let clientAuthKey = NIOSSHPrivateKey(ed25519Key: .init())

        // We use the Secure Enclave keys for everything, just because we can.
        var harness = TestHarness()
        harness.transportProtectionAlgoritms = [CustomTransportProtection.self]
        harness.serverHostKeys = [hostKey]
        harness.clientAuthDelegate = PrivateKeyClientAuth(clientAuthKey)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(clientAuthKey.publicKey)

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel, again, just because we can.
        _ = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
        XCTAssertTrue(CustomTransportProtection.wasUsed)
    }
    
    func testCustomKeyExchangeAlgorithms() throws {
        NIOSSHAlgorithms.unregisterAlgorithms()
        CustomKeyExchange.wasUsed = false
        NIOSSHAlgorithms.register(keyExchangeAlgorithm: CustomKeyExchange.self)
        NIOSSHAlgorithms.register(publicKey: CustomPublicKey.self, signature: CustomSignature.self)
        
        // If we can't create this key, we skip the test.
        let hostKey = NIOSSHPrivateKey(custom: CustomPrivateKey())
        let clientAuthKey = NIOSSHPrivateKey(ed25519Key: .init())

        // We use the Secure Enclave keys for everything, just because we can.
        var harness = TestHarness()
        harness.keyExchangeAlgorithms = [CustomKeyExchange.self]
        harness.serverHostKeys = [hostKey]
        harness.clientAuthDelegate = PrivateKeyClientAuth(clientAuthKey)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(clientAuthKey.publicKey)

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel, again, just because we can.
        _ = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
        XCTAssertTrue(CustomKeyExchange.wasUsed)
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

    func testDelayedHostKeyValidation() throws {
        class DelayedValidationDelegate: NIOSSHClientServerAuthenticationDelegate {
            var validationCount = 0

            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                // Short delay here, but we'll be forced to wait.
                validationCompletePromise.futureResult.eventLoop.scheduleTask(in: .milliseconds(100)) {
                    self.validationCount += 1
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
        XCTAssertNoThrow(try self.channel.client.pipeline.addHandler(errorCatcher).wait())
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
        XCTAssertNoThrow(try self.channel.client.pipeline.addHandler(ErrorClosingHandler()).wait())

        // Get an early ref to the handler and try to create a child channel.
        let handler = self.channel.clientSSHHandler

        var err: Error?
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err = error }
        handler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        XCTAssertNil(err)

        // Activation errors.
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertThrowsError(try self.channel.interactInMemory()) { error in
            XCTAssertEqual(error as? TestError, .bang)
        }
        self.channel.run()
        XCTAssertEqual(err as? ChannelError?, .eof)
    }

    func testCreateChannelAfterDisconnectFailsWithEventLoopTick() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate disconnection on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._disconnect())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Attempting to create a child channel should immediately fail.
        var err: Error?
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err = error }
        self.channel.clientSSHHandler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        self.channel.run()

        XCTAssertNotNil(err)
        XCTAssertEqual((err as? NIOSSHError)?.type, .creatingChannelAfterClosure)
    }

    func testCreateChannelAfterDisconnectFailsWithoutEventLoopTick() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate disconnection on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._disconnect())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Attempting to create a child channel should immediately fail.
        var err: Error?
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err = error }
        self.channel.clientSSHHandler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        self.channel.run()

        XCTAssertNotNil(err)
        XCTAssertEqual((err as? NIOSSHError)?.type, .creatingChannelAfterClosure)
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
        XCTAssertNoThrow(try self.channel.client.pipeline.addHandler(handshaker).wait())
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
        XCTAssertNoThrow(try self.channel.client.pipeline.addHandler(handshaker).wait())
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
        harness.serverAuthBanner = .init(message: ClientHandshakeHandler.expectedAuthBannerMessage, languageTag: ClientHandshakeHandler.expectedAuthBannerLanguageTag)

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.addHandler(handshaker).wait())
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
            func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
                nextChallengePromise.fail(TestError.bang)
            }
        }

        var harness = TestHarness()
        harness.clientAuthDelegate = BadPasswordDelegate()

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.addHandler(handshaker).wait())
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertThrowsError(try promise.futureResult.wait()) { error in
            XCTAssertEqual(error as? TestError, TestError.bang)
        }
    }
}
