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
import NIO
@testable import NIOSSH
import XCTest

private enum Fixtures {
    // P256 ECDSA key, generated using `ssh-keygen -m PEM -t ecdsa`
    static let privateKey = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIJFqt5pH9xGvuoaI5kzisthTa0EXVgy+fC4bAtdwBR07oAoGCCqGSM49
    AwEHoUQDQgAEyJP6dnY46GvyP65L9FgFxNdN+rNWy4PqIwCrwJWY6ss/sTSbMkdA
    4D7gh+fWyft3EdRtcAsw3raU/G2S+N1iAA==
    -----END EC PRIVATE KEY-----
    """

    // Raw private key data, since `PrivateKey(pemRepresentation:)` is not available on every supported platform
    static let privateKeyRaw = Data([145, 106, 183, 154, 71, 247, 17, 175, 186, 134, 136, 230, 76, 226, 178, 216, 83, 107, 65, 23, 86, 12, 190, 124, 46, 27, 2, 215, 112, 5, 29, 59])

    // A P256 user key. id "User P256 key" serial 0 for foo,bar valid from 2020-06-03T17:50:15 to 2070-04-02T17:51:15
    // Generated using ssh-keygen -s ca-key -I "User P256 key" -n "foo,bar" -V "-1m:+2600w" user-p256
    static let certificateKey = """
    ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHmvoERZ+BRKhlCAKoPlVQLcHO5oNxyGeXHnmI0DLL/8AAAAIbmlzdHAyNTYAAABBBMiT+nZ2OOhr8j+uS/RYBcTXTfqzVsuD6iMAq8CVmOrLP7E0mzJHQOA+4Ifn1sn7dxHUbXALMN62lPxtkvjdYgAAAAAAAAAAAAAAAAEAAAANVXNlciBQMjU2IGtleQAAAA4AAAADZm9vAAAAA2JhcgAAAABgABLaAAAAAL26NxYAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAiAAAABNlY2RzYS1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQR2JTEl2nF7dd6AS6TFxD9DkjMOaJHeXOxt4aIptTEf0x1DsjktgFUChKi2bPrXd2OsmAq6uUxlgzRmNnXyhV/fZy6iQqtpMUf/wj91IXq5GZ5+ruHluG4iy+8Tg6jTs5EAAACDAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAABoAAAAMHIoH34qNeg6LDTiSUF13KvPImQljh1Se5cxtrZZ3bCBAK2DUZQsAitxc8Ju4jY2zQAAADBkQfjSYa5wr2y61D54kWSIDiqOjgEAnfjJkyglQcYU4P1ULCFXJ15tIg3GRBY4U/s= artemredkin@Artems-MacBook-Pro.local
    """
}

/// An authentication delegate that yields passwords forever.
final class InfinitePasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        let request = NIOSSHUserAuthenticationOffer(username: "foo", serviceName: "", offer: .password(.init(password: "bar")))
        nextChallengePromise.succeed(request)
    }
}

final class InfinitePrivateKeyDelegate: NIOSSHClientUserAuthenticationDelegate {
    let key = NIOSSHPrivateKey(p256Key: .init())

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        let request = NIOSSHUserAuthenticationOffer(username: "foo", serviceName: "", offer: .privateKey(.init(privateKey: self.key)))
        nextChallengePromise.succeed(request)
    }
}

final class InfiniteCertificateDelegate: NIOSSHClientUserAuthenticationDelegate {
    let privateKey: NIOSSHPrivateKey
    let certifiedKey: NIOSSHCertifiedPublicKey

    init() throws {
        self.privateKey = try NIOSSHPrivateKey(p256Key: P256.Signing.PrivateKey(rawRepresentation: Fixtures.privateKeyRaw))
        self.certifiedKey = try NIOSSHCertifiedPublicKey(NIOSSHPublicKey(openSSHPublicKey: Fixtures.certificateKey))!
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        let request = NIOSSHUserAuthenticationOffer(username: "foo", serviceName: "", offer: .privateKey(.init(privateKey: self.privateKey, certifiedKey: self.certifiedKey)))
        nextChallengePromise.succeed(request)
    }
}

/// An authentication delegate that denies some number of requests and then accepts exactly one and fails the rest.
final class DenyThenAcceptDelegate: NIOSSHServerUserAuthenticationDelegate {
    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .all

    private var messagesToDeny: Int

    init(messagesToDeny: Int) {
        self.messagesToDeny = messagesToDeny
    }

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        let messages = self.messagesToDeny
        self.messagesToDeny -= 1

        switch messages {
        case 0:
            responsePromise.succeed(.success)
        default:
            responsePromise.succeed(.failure)
        }
    }
}

final class UserAuthenticationStateMachineTests: XCTestCase {
    var loop: EmbeddedEventLoop!
    var hostKey: NIOSSHPrivateKey!
    var sessionID: ByteBuffer!

    override func setUp() {
        self.loop = EmbeddedEventLoop()
        self.hostKey = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey())

        // We use a SHA256-sized session ID, not that it matters much.
        var buffer = ByteBufferAllocator().buffer(capacity: 32)
        buffer.writeBytes(0 ..< 32)
        self.sessionID = buffer
    }

    override func tearDown() {
        try! self.loop.syncShutdownGracefully()
        self.loop = nil
        self.hostKey = nil
    }

    func beginAuthentication(stateMachine: inout UserAuthenticationStateMachine) throws {
        let expectedMessage = SSHMessage.ServiceRequestMessage(service: "ssh-userauth")
        let request: SSHMessage.ServiceRequestMessage? = try assertNoThrowWithValue(stateMachine.beginAuthentication())
        XCTAssertEqual(request, expectedMessage)
    }

    func serviceRequested(service: String, nextMessage expectedMessage: SSHMessage.ServiceAcceptMessage?, stateMachine: inout UserAuthenticationStateMachine) throws {
        let request = SSHMessage.ServiceRequestMessage(service: service)
        let response = try assertNoThrowWithValue(stateMachine.receiveServiceRequest(request))
        XCTAssertEqual(response, expectedMessage)
    }

    func serviceAccepted(service: String, nextMessage expectedMessage: SSHMessage.UserAuthRequestMessage?, userAuthPayload: UserAuthSignablePayload? = nil, stateMachine: inout UserAuthenticationStateMachine) throws {
        var request: SSHMessage.UserAuthRequestMessage?

        let future = try assertNoThrowWithValue(stateMachine.receiveServiceAccept(.init(service: service)))
        XCTAssertNotNil(future)
        future?.whenComplete {
            switch $0 {
            case .success(let message):
                request = message
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
        }
        self.loop.run()

        // For signed methods we need to be a bit careful: we can't assume that the signature will have a bitwise match, so we have to validate it
        // instead.
        if case .some(.publicKey(.known(let expectedKey, _))) = expectedMessage.map({ $0.method }),
            case .some(.publicKey(.known(let actualKey, let actualSignature))) = request.map({ $0.method }),
            let userAuthPayload = userAuthPayload {
            XCTAssertEqual(expectedMessage!.username, request!.username)
            XCTAssertEqual(expectedMessage!.service, request!.service)
            XCTAssertEqual(expectedKey, actualKey)
            XCTAssertTrue(expectedKey.isValidSignature(actualSignature!, for: userAuthPayload))
        } else {
            XCTAssertEqual(request, expectedMessage)
        }
    }

    func authFailed(failure: SSHMessage.UserAuthFailureMessage, nextMessage expectedMessage: SSHMessage.UserAuthRequestMessage?, userAuthPayload: UserAuthSignablePayload? = nil, stateMachine: inout UserAuthenticationStateMachine) throws {
        var request: SSHMessage.UserAuthRequestMessage?

        let future = try assertNoThrowWithValue(stateMachine.receiveUserAuthFailure(failure))
        XCTAssertNotNil(future)
        future?.whenComplete {
            switch $0 {
            case .success(let message):
                request = message
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
        }
        self.loop.run()

        // For signed methods we need to be a bit careful: we can't assume that the signature will have a bitwise match, so we have to validate it
        // instead.
        if case .some(.publicKey(.known(let expectedKey, _))) = expectedMessage.map({ $0.method }),
            case .some(.publicKey(.known(let actualKey, let actualSignature))) = request.map({ $0.method }),
            let userAuthPayload = userAuthPayload {
            XCTAssertEqual(expectedMessage!.username, request!.username)
            XCTAssertEqual(expectedMessage!.service, request!.service)
            XCTAssertEqual(expectedKey, actualKey)
            XCTAssertTrue(expectedKey.isValidSignature(actualSignature!, for: userAuthPayload))
        } else {
            XCTAssertEqual(request, expectedMessage)
        }
    }

    func expectAuthRequestToFailSynchronously(request: SSHMessage.UserAuthRequestMessage, expecting result: SSHMessage.UserAuthFailureMessage, stateMachine: inout UserAuthenticationStateMachine) throws {
        var message: SSHMessage.UserAuthFailureMessage?

        let future = try assertNoThrowWithValue(try stateMachine.receiveUserAuthRequest(request))
        XCTAssertNotNil(future)
        future?.whenComplete {
            switch $0 {
            case .success(.failure(let response)):
                message = response
            case .success(.publicKeyOK):
                XCTFail("Unexpected public key ok")
            case .success(.success):
                XCTFail("Unexpected success")
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
        }
        self.loop.run()

        XCTAssertEqual(message, result)
    }

    func expectAuthRequestToSucceedSynchronously(request: SSHMessage.UserAuthRequestMessage, stateMachine: inout UserAuthenticationStateMachine) throws {
        var completed = false

        let future = try assertNoThrowWithValue(try stateMachine.receiveUserAuthRequest(request))
        XCTAssertNotNil(future)
        future?.whenComplete {
            switch $0 {
            case .success(.success):
                completed = true
            case .success(.publicKeyOK):
                XCTFail("Unexpected public key ok")
            case .success(.failure):
                XCTFail("Unexpected failure")
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
        }
        self.loop.run()

        XCTAssertTrue(completed)
    }

    func expectAuthRequestToReturnPKOKSynchronously(request: SSHMessage.UserAuthRequestMessage, expecting: SSHMessage.UserAuthPKOKMessage, stateMachine: inout UserAuthenticationStateMachine) throws {
        var message: SSHMessage.UserAuthPKOKMessage?

        let future = try assertNoThrowWithValue(try stateMachine.receiveUserAuthRequest(request))
        XCTAssertNotNil(future)
        future?.whenComplete {
            switch $0 {
            case .success(.publicKeyOK(let response)):
                message = response
            case .success(.success):
                XCTFail("Unexpected success")
            case .success(.failure):
                XCTFail("Unexpected failure")
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
        }
        self.loop.run()

        XCTAssertEqual(message, expecting)
    }

    func testBasicHappyClientFlow() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let firstMessage = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        XCTAssertNoThrow(try self.serviceAccepted(service: "ssh-userauth", nextMessage: firstMessage, stateMachine: &stateMachine))
        stateMachine.sendUserAuthRequest(firstMessage)

        // Let's say we got a success. Happy path!
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
    }

    func testBasicSadClientFlow() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let firstMessage = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        XCTAssertNoThrow(try self.serviceAccepted(service: "ssh-userauth", nextMessage: firstMessage, stateMachine: &stateMachine))
        stateMachine.sendUserAuthRequest(firstMessage)

        // Oh no, a failure!
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["password"], partialSuccess: false)
        try self.authFailed(failure: failure, nextMessage: nil, stateMachine: &stateMachine)

        // We're done.
        stateMachine.noFurtherMethods()
    }

    func testBasicSadThenHappyClientFlow() throws {
        let delegate = InfinitePasswordDelegate()
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let firstMessage = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        XCTAssertNoThrow(try self.serviceAccepted(service: "ssh-userauth", nextMessage: firstMessage, stateMachine: &stateMachine))
        stateMachine.sendUserAuthRequest(firstMessage)

        // Oh no, a failure! We'll try again.
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["password"], partialSuccess: false)
        try self.authFailed(failure: failure, nextMessage: firstMessage, stateMachine: &stateMachine)
        stateMachine.sendUserAuthRequest(firstMessage)

        // Let's say we got a success. Happy path!
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
    }

    func testAuthMessagesAfterSuccessAreIgnored() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let firstMessage = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        XCTAssertNoThrow(try self.serviceAccepted(service: "ssh-userauth", nextMessage: firstMessage, stateMachine: &stateMachine))
        stateMachine.sendUserAuthRequest(firstMessage)

        // Let's say we got a success. Happy path!
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())

        // Ok, the following two messages should be ignored.
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
        XCTAssertNoThrow(try stateMachine.receiveUserAuthFailure(.init(authentications: ["password"], partialSuccess: false)))
    }

    func testUnsolicitedResponseBeforeInitIsInvalid() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertThrowsError(try stateMachine.receiveUserAuthSuccess()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
        XCTAssertThrowsError(try stateMachine.receiveUserAuthFailure(.init(authentications: ["password"], partialSuccess: false))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testUnsolicitedResponseAfterInitBeforeSendingIsInvalid() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        // Let's request the first message but not deliver it.
        _ = stateMachine.beginAuthentication()

        XCTAssertThrowsError(try stateMachine.receiveUserAuthSuccess()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
        XCTAssertThrowsError(try stateMachine.receiveUserAuthFailure(.init(authentications: ["password"], partialSuccess: false))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testUnsolicitedResponseAfterFailureBeforeNextRequestIsInvalid() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let firstMessage = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        XCTAssertNoThrow(try self.serviceAccepted(service: "ssh-userauth", nextMessage: firstMessage, stateMachine: &stateMachine))
        stateMachine.sendUserAuthRequest(firstMessage)

        // Oh no, a failure!
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["password"], partialSuccess: false)
        try self.authFailed(failure: failure, nextMessage: nil, stateMachine: &stateMachine)

        // Don't tell the state machine that there are no more records, deliver the responses now.
        XCTAssertThrowsError(try stateMachine.receiveUserAuthSuccess()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
        XCTAssertThrowsError(try stateMachine.receiveUserAuthFailure(.init(authentications: ["password"], partialSuccess: false))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testUnsolicitedResponseAfterCompleteFailureIsInvalid() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let firstMessage = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        XCTAssertNoThrow(try self.serviceAccepted(service: "ssh-userauth", nextMessage: firstMessage, stateMachine: &stateMachine))
        stateMachine.sendUserAuthRequest(firstMessage)

        // Oh no, a failure!
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["password"], partialSuccess: false)
        try self.authFailed(failure: failure, nextMessage: nil, stateMachine: &stateMachine)

        // Tell the state machine we've truly failed.
        stateMachine.noFurtherMethods()

        // These responses are invalid.
        XCTAssertThrowsError(try stateMachine.receiveUserAuthSuccess()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
        XCTAssertThrowsError(try stateMachine.receiveUserAuthFailure(.init(authentications: ["password"], partialSuccess: false))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testServersMayNotReceiveUserAuthSuccessMessages() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyAllServerAuthDelegate())), loop: self.loop, sessionID: self.sessionID)

        // Deliver a user auth success message
        XCTAssertThrowsError(try stateMachine.receiveUserAuthSuccess()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testServersMayNotReceiveUserAuthFailureMessages() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyAllServerAuthDelegate())), loop: self.loop, sessionID: self.sessionID)

        // Deliver a user auth failure message
        let message = SSHMessage.UserAuthFailureMessage(authentications: [], partialSuccess: false)
        XCTAssertThrowsError(try stateMachine.receiveUserAuthFailure(message)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testBasicServerRejections() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyAllServerAuthDelegate())), loop: self.loop, sessionID: self.sessionID)

        // Begin by doing the service accept dance.
        let serviceAccept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertNoThrow(try self.serviceRequested(service: "ssh-userauth", nextMessage: serviceAccept, stateMachine: &stateMachine))
        stateMachine.sendServiceAccept(serviceAccept)

        // User asks a question, it fails.
        let authRequest = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["password", "publickey", "hostbased"], partialSuccess: false)
        try self.expectAuthRequestToFailSynchronously(request: authRequest, expecting: failure, stateMachine: &stateMachine)
        stateMachine.sendUserAuthFailure(failure)

        // User asks again, fails again.
        try self.expectAuthRequestToFailSynchronously(request: authRequest, expecting: failure, stateMachine: &stateMachine)
        stateMachine.sendUserAuthFailure(failure)
    }

    func testManyAuthRequestsInFlightAtOnce() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyAllServerAuthDelegate())), loop: self.loop, sessionID: self.sessionID)

        // Begin by doing the service accept dance.
        let serviceAccept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertNoThrow(try self.serviceRequested(service: "ssh-userauth", nextMessage: serviceAccept, stateMachine: &stateMachine))
        stateMachine.sendServiceAccept(serviceAccept)

        // The user can ask many questions in parallel.
        let authRequest = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["password", "publickey", "hostbased"], partialSuccess: false)

        for _ in 0 ..< 10 {
            try self.expectAuthRequestToFailSynchronously(request: authRequest, expecting: failure, stateMachine: &stateMachine)
        }
        for _ in 0 ..< 10 {
            stateMachine.sendUserAuthFailure(failure)
        }
    }

    func testSimpleServerHappyPath() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0))), loop: self.loop, sessionID: self.sessionID)

        // Begin by doing the service accept dance.
        let serviceAccept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertNoThrow(try self.serviceRequested(service: "ssh-userauth", nextMessage: serviceAccept, stateMachine: &stateMachine))
        stateMachine.sendServiceAccept(serviceAccept)

        // We get a request.
        let authRequest = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        try self.expectAuthRequestToSucceedSynchronously(request: authRequest, stateMachine: &stateMachine)
        stateMachine.sendUserAuthSuccess()
    }

    func testServerIgnoresMessagesAfterSuccess() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0))), loop: self.loop, sessionID: self.sessionID)

        // Begin by doing the service accept dance.
        let serviceAccept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertNoThrow(try self.serviceRequested(service: "ssh-userauth", nextMessage: serviceAccept, stateMachine: &stateMachine))
        stateMachine.sendServiceAccept(serviceAccept)

        // We get a request, which succeeds.
        let authRequest = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        try self.expectAuthRequestToSucceedSynchronously(request: authRequest, stateMachine: &stateMachine)
        stateMachine.sendUserAuthSuccess()

        // Let's try getting another request. This will be ignored.
        let future = try assertNoThrowWithValue(stateMachine.receiveUserAuthRequest(authRequest))
        XCTAssertNil(future)
    }

    func testClientRejectsUserAuthRequests() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)
        let authRequest = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))

        XCTAssertThrowsError(try stateMachine.receiveUserAuthRequest(authRequest)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testSimplePasswordDelegateOnlyTriesPassword() throws {
        // This branch isn't really reachable in the current code, but we should verify SimplePasswordDelegate only likes
        // passwords!
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        let challengePromise = self.loop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        delegate.nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods.all.subtracting(.password),
                                        nextChallengePromise: challengePromise)
        self.loop.run()

        let result = try assertNoThrowWithValue(challengePromise.futureResult.wait())
        XCTAssertNil(result)
    }

    func testBeginningAuthenticationOnServersDoesNothing() throws {
        let stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0))), loop: self.loop, sessionID: self.sessionID)
        XCTAssertNil(stateMachine.beginAuthentication())
    }

    func testRejectUnexpectedServices() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0))), loop: self.loop, sessionID: self.sessionID)

        let request = SSHMessage.ServiceRequestMessage(service: "ssh-connection")
        XCTAssertThrowsError(try stateMachine.receiveServiceRequest(request)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testRepeatedServiceRequestsDontWork() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0))), loop: self.loop, sessionID: self.sessionID)

        // Begin by doing the service accept dance.
        let serviceAccept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertNoThrow(try self.serviceRequested(service: "ssh-userauth", nextMessage: serviceAccept, stateMachine: &stateMachine))

        // A second received service request is rejected.
        let request = SSHMessage.ServiceRequestMessage(service: "ssh-userauth")
        XCTAssertThrowsError(try stateMachine.receiveServiceRequest(request)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }

        stateMachine.sendServiceAccept(serviceAccept)

        // And here too.
        XCTAssertThrowsError(try stateMachine.receiveServiceRequest(request)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }

        // We get a request.
        let authRequest = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        try self.expectAuthRequestToSucceedSynchronously(request: authRequest, stateMachine: &stateMachine)

        // And here too.
        XCTAssertThrowsError(try stateMachine.receiveServiceRequest(request)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }

        stateMachine.sendUserAuthSuccess()

        // Now a duplicate service request is ignored.
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.receiveServiceRequest(request)))
    }

    func testClientsRejectUserAuthRequests() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertThrowsError(try stateMachine.receiveServiceRequest(.init(service: "ssh-userauth"))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testClientsRejectUnexpectedAuthServices() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let response = SSHMessage.ServiceAcceptMessage(service: "ssh-connection")
        XCTAssertThrowsError(try stateMachine.receiveServiceAccept(response)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testClientsRejectServiceAcceptOutOfSequence() throws {
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        // Before we start the client rejects service accepts.
        let accept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertThrowsError(try stateMachine.receiveServiceAccept(accept)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let firstMessage = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        XCTAssertNoThrow(try self.serviceAccepted(service: "ssh-userauth", nextMessage: firstMessage, stateMachine: &stateMachine))

        // Here the client rejects service accepts.
        XCTAssertThrowsError(try stateMachine.receiveServiceAccept(accept)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }

        stateMachine.sendUserAuthRequest(firstMessage)

        // And here.
        XCTAssertThrowsError(try stateMachine.receiveServiceAccept(accept)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }

        var stateCopy = stateMachine

        // Let's say we got a success. Happy path!
        XCTAssertNoThrow(try stateCopy.receiveUserAuthSuccess())

        // Here the client ignores the message.
        XCTAssertNoThrow(XCTAssertNil(try stateCopy.receiveServiceAccept(accept)))

        // And let's instead say we failed.
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["password"], partialSuccess: false)
        let futureResult = try assertNoThrowWithValue(stateMachine.receiveUserAuthFailure(failure))!
        XCTAssertNoThrow(XCTAssertNil(try futureResult.wait()))

        // Here the client rejects the message.
        XCTAssertThrowsError(try stateMachine.receiveServiceAccept(accept)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testServerRejectsServiceAccepts() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyAllServerAuthDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertThrowsError(try stateMachine.receiveServiceAccept(.init(service: "ssh-userauth"))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testUserAuthRequestsMustAskForSSHConnection() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyAllServerAuthDelegate())), loop: self.loop, sessionID: self.sessionID)

        // Begin by doing the service accept dance.
        let serviceAccept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertNoThrow(try self.serviceRequested(service: "ssh-userauth", nextMessage: serviceAccept, stateMachine: &stateMachine))
        stateMachine.sendServiceAccept(serviceAccept)

        // User asks a question, it fails.
        let authRequest = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-something-weird", method: .password("bar"))
        XCTAssertThrowsError(try stateMachine.receiveUserAuthRequest(authRequest)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testUserAuthBeforeServiceAcceptIsRejected() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyAllServerAuthDelegate())), loop: self.loop, sessionID: self.sessionID)

        // User asks a question too early.
        let authRequest = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
        XCTAssertThrowsError(try stateMachine.receiveUserAuthRequest(authRequest)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }

        // Begin by doing the service accept dance.
        let serviceAccept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertNoThrow(try self.serviceRequested(service: "ssh-userauth", nextMessage: serviceAccept, stateMachine: &stateMachine))

        // Still not allowed here.
        XCTAssertThrowsError(try stateMachine.receiveUserAuthRequest(authRequest)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testPrivateKeyServerAuthFlowP256() throws {
        try self.privateKeyServerAuthFlow(.init(p256Key: .init()))
    }

    func testPrivateKeyServerAuthFlowP384() throws {
        try self.privateKeyServerAuthFlow(.init(p384Key: .init()))
    }

    func testPrivateKeyServerAuthFlowP521() throws {
        try self.privateKeyServerAuthFlow(.init(p521Key: .init()))
    }

    func privateKeyServerAuthFlow(_ newKey: NIOSSHPrivateKey) throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1))), loop: self.loop, sessionID: self.sessionID)

        // Begin by doing the service accept dance.
        let serviceAccept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertNoThrow(try self.serviceRequested(service: "ssh-userauth", nextMessage: serviceAccept, stateMachine: &stateMachine))
        stateMachine.sendServiceAccept(serviceAccept)

        // User first issues a private key query. We auto-accept this, it doesn't affect the delegate.
        let query = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .publicKey(.known(key: self.hostKey.publicKey, signature: nil)))
        let response = SSHMessage.UserAuthPKOKMessage(key: self.hostKey.publicKey)
        try self.expectAuthRequestToReturnPKOKSynchronously(request: query, expecting: response, stateMachine: &stateMachine)
        stateMachine.sendUserAuthPKOK(response)

        // Now the user issues the actual query. This fails.
        let payload = UserAuthSignablePayload(sessionIdentifier: self.sessionID, userName: "foo", serviceName: "ssh-connection", publicKey: self.hostKey.publicKey)
        let signature = try self.hostKey.sign(payload)
        let request = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .publicKey(.known(key: self.hostKey.publicKey, signature: signature)))
        try self.expectAuthRequestToFailSynchronously(request: request,
                                                      expecting: .init(authentications: NIOSSHAvailableUserAuthenticationMethods.all.strings, partialSuccess: false),
                                                      stateMachine: &stateMachine)
        stateMachine.sendUserAuthFailure(.init(authentications: NIOSSHAvailableUserAuthenticationMethods.all.strings, partialSuccess: false))

        // Ok, let's do another query with a different key type. This time we won't bother with the little preamble dance, we'll just go straight to
        // querying: this should be fine too.
        let payload2 = UserAuthSignablePayload(sessionIdentifier: self.sessionID, userName: "foo", serviceName: "ssh-connection", publicKey: newKey.publicKey)
        let newSignature = try newKey.sign(payload2)
        let request2 = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .publicKey(.known(key: newKey.publicKey, signature: newSignature)))
        try self.expectAuthRequestToSucceedSynchronously(request: request2, stateMachine: &stateMachine)
        stateMachine.sendUserAuthSuccess()
    }

    func testServerPerformsValidationsOnSignatures() throws {
        var stateMachine = UserAuthenticationStateMachine(role: .server(.init(hostKeys: [self.hostKey], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0))), loop: self.loop, sessionID: self.sessionID)

        // Begin by doing the service accept dance.
        let serviceAccept = SSHMessage.ServiceAcceptMessage(service: "ssh-userauth")
        XCTAssertNoThrow(try self.serviceRequested(service: "ssh-userauth", nextMessage: serviceAccept, stateMachine: &stateMachine))
        stateMachine.sendServiceAccept(serviceAccept)

        // We're going to sign the wrong data.
        let signature = try self.hostKey.sign(digest: SHA256.hash(data: Array("this is not the data we should be signing".utf8)))
        let request = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .publicKey(.known(key: self.hostKey.publicKey, signature: signature)))
        try self.expectAuthRequestToFailSynchronously(request: request,
                                                      expecting: .init(authentications: NIOSSHAvailableUserAuthenticationMethods.all.strings, partialSuccess: false),
                                                      stateMachine: &stateMachine)
        stateMachine.sendUserAuthFailure(.init(authentications: NIOSSHAvailableUserAuthenticationMethods.all.strings, partialSuccess: false))
    }

    func testPrivateKeyClientAuthFlow() throws {
        let delegate = InfinitePrivateKeyDelegate()
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let dataToSign = UserAuthSignablePayload(sessionIdentifier: self.sessionID, userName: "foo", serviceName: "ssh-connection", publicKey: delegate.key.publicKey)
        let signature = try delegate.key.sign(dataToSign)
        let firstMessage = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .publicKey(.known(key: delegate.key.publicKey, signature: signature)))
        XCTAssertNoThrow(try self.serviceAccepted(service: "ssh-userauth", nextMessage: firstMessage, userAuthPayload: dataToSign, stateMachine: &stateMachine))
        stateMachine.sendUserAuthRequest(firstMessage)

        // Oh no, a failure! We'll try again.
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["publickey"], partialSuccess: false)
        try self.authFailed(failure: failure, nextMessage: firstMessage, userAuthPayload: dataToSign, stateMachine: &stateMachine)
        stateMachine.sendUserAuthRequest(firstMessage)

        // Let's say we got a success. Happy path!
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
    }

    func testCertificateClientAuthFlow() throws {
        let delegate = try InfiniteCertificateDelegate()
        var stateMachine = UserAuthenticationStateMachine(role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), loop: self.loop, sessionID: self.sessionID)

        XCTAssertNoThrow(try self.beginAuthentication(stateMachine: &stateMachine))
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let dataToSign = UserAuthSignablePayload(sessionIdentifier: self.sessionID, userName: "foo", serviceName: "ssh-connection", publicKey: NIOSSHPublicKey(delegate.certifiedKey))
        let signature = try delegate.privateKey.sign(dataToSign)

        let firstMessage = SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .publicKey(.known(key: NIOSSHPublicKey(delegate.certifiedKey), signature: signature)))
        XCTAssertNoThrow(try self.serviceAccepted(service: "ssh-userauth", nextMessage: firstMessage, userAuthPayload: dataToSign, stateMachine: &stateMachine))
        stateMachine.sendUserAuthRequest(firstMessage)

        // Oh no, a failure! We'll try again.
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["publickey"], partialSuccess: false)
        try self.authFailed(failure: failure, nextMessage: firstMessage, userAuthPayload: dataToSign, stateMachine: &stateMachine)
        stateMachine.sendUserAuthRequest(firstMessage)

        // Let's say we got a success. Happy path!
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
    }
}
