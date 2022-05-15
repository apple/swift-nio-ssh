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
    func tcpForwardingRequest(_: GlobalRequest.TCPForwardingRequest, handler: NIOSSHHandler, promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>)
}

extension GlobalRequestDelegate {
    public func tcpForwardingRequest(_ request: GlobalRequest.TCPForwardingRequest, handler: NIOSSHHandler, promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>) {
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

    /// The data associated with a successful response to a TCP forwarding request.
    public struct TCPForwardingResponse: Hashable {
        /// If requested to listen on a port, and the port the client requested was 0, this is set to the
        /// port that was actually bound. Otherwise is nil.
        public var boundPort: Int?

        public init(boundPort: Int?) {
            self.boundPort = boundPort
        }
    }

    enum GlobalRequestResponse: Equatable {
        case tcpForwarding(TCPForwardingResponse)
        case unknown(ByteBuffer)
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

extension GlobalRequest.TCPForwardingResponse {
    internal init(_ response: SSHMessage.RequestSuccessMessage) {
        var data = response.buffer
        if let boundPort = data.readInteger(as: UInt32.self) {
            self.boundPort = Int(boundPort)
        }
    }
}

extension SSHMessage.RequestSuccessMessage {
    internal init(_ request: GlobalRequest.GlobalRequestResponse, allocator: ByteBufferAllocator) {
        switch request {
        case .tcpForwarding(let response):
            var buffer = allocator.buffer(capacity: 4)
            if let port = response.boundPort {
                buffer.writeInteger(UInt32(port))
            }
            self.buffer = buffer
        case .unknown(let buffer):
            self.buffer = buffer
        }
    }
}
