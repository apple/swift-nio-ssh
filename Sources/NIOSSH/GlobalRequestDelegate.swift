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
    func tcpForwardingRequest(_: GlobalRequest.TCPForwardingRequest, promise: EventLoopPromise<Void>)
}

extension GlobalRequestDelegate {
    func tcpForwardingRequest(_ request: GlobalRequest.TCPForwardingRequest, promise: EventLoopPromise<Void>) {
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
        case listen(SocketAddress)

        /// A request to stop listening on a given address.
        case cancel(SocketAddress)
    }
}

/// The internal default global request delegate rejects all requests.
internal struct DefaultGlobalRequestDelegate: GlobalRequestDelegate { }
