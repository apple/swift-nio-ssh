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

/// A `GlobalRequestDelegate` is used by an SSH server to handle SSH global requests.
///
/// These are requests for connection-wide SSH resources. Today the only global requests
/// available are for managing TCP port forwarding: specifically, they allow clients to
/// request that the server listen on a port for it.
///
/// All delegate methods for this delegate are optional: if not implemented, they default to rejecting
/// all requests of a given type.
public protocol GlobalRequestDelegate {
    /// The client wants to manage TCP port forwarding.
    func tcpForwardingRequest(_: GlobalRequest.TCPForwardingRequest, handler: NIOSSHHandler, promise: EventLoopPromise<GlobalRequest.GlobalRequestResponse>)
}

extension GlobalRequestDelegate {
    func tcpForwardingRequest(_ request: GlobalRequest.TCPForwardingRequest, handler: NIOSSHHandler, promise: EventLoopPromise<GlobalRequest.GlobalRequestResponse>) {
        // The default implementation rejects all requests.
        promise.fail(NIOSSHError.unsupportedGlobalRequest)
    }
}

/// A namespace of `GlobalRequest` objects that delegates may be asked to handle.
public enum GlobalRequest {
    /// A request from a client to a server for the server to listen on a port on the client's behalf. If accepted,
    /// the server will listen on a port, and will forward accepted connections to the client using the "forwarded-tcpip"
    /// channel type.
    public enum TCPForwardingRequest: Equatable {
        /// A request to listen on a given address.
        case listen(host: String, port: Int)

        /// A request to stop listening on a given address.
        case cancel(host: String, port: Int)
    }

    /// The data associated with a successful response to a global request.
    public struct GlobalRequestResponse: Hashable {
        /// If requested to listen on a port, and the port the client requested was 0, this is set to the
        /// port that was actually bound. Otherwise is nil.
        public var boundPort: Int?

        public init(boundPort: Int?) {
            self.boundPort = boundPort
        }
    }
}

/// The internal default global request delegate rejects all requests.
internal struct DefaultGlobalRequestDelegate: GlobalRequestDelegate {}

extension SSHMessage.GlobalRequestMessage.RequestType {
    internal init(_ request: GlobalRequest.TCPForwardingRequest) {
        switch request {
        case .listen(host: let host, port: let port):
            self = .tcpipForward(host, UInt32(port))

        case .cancel(host: let host, port: let port):
            self = .cancelTcpipForward(host, UInt32(port))
        }
    }
}

extension SSHMessage.RequestSuccessMessage {
    internal init(_ response: GlobalRequest.GlobalRequestResponse) {
        self.boundPort = response.boundPort.map { UInt32($0) }
    }
}

extension GlobalRequest.TCPForwardingRequest {
    internal init?(_ message: SSHMessage.GlobalRequestMessage) {
        switch message.type {
        case .tcpipForward(let host, let port):
            self = .listen(host: host, port: Int(port))
        case .cancelTcpipForward(let host, let port):
            self = .cancel(host: host, port: Int(port))
        case .unknown:
            return nil
        }
    }
}

extension GlobalRequest.GlobalRequestResponse {
    internal init(_ response: SSHMessage.RequestSuccessMessage) {
        self.boundPort = response.boundPort.map { Int($0) }
    }
}
