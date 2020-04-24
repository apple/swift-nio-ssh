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

/// The result of a round of key exchange.
///
/// A round of key exchange generates a number of keys and also generates an exchange hash.
/// This exchange hash is used for a number of purposes.
struct KeyExchangeResult {
    /// The session ID to use for this connection. Will be static across the lifetime of a connection.
    var sessionID: ByteBuffer

    var keys: NIOSSHSessionKeys
}

extension KeyExchangeResult: Equatable {}

/// The session keys generated as a result of a round of key exchange.
///
/// SSH key exchange generates one shared secret, which is then used to generate
/// 6 pieces of data:
///
/// 1. Initial IV, client to server
/// 2. Initial IV, server to client
/// 3. Encryption key, client to server
/// 4. Encryption key, server to client
/// 5. MAC key, client to server
/// 6. MAC key, server to client.
///
/// This object represents these 6 pieces of data using appropriate data types to record
/// them.
///
/// Of these types, the encryption keys and the MAC keys are intended to be secret, and so
/// we store them in the `SymmetricKey` types. The IVs do not need to be secret, and so are
/// stored in regular heap buffers.
struct NIOSSHSessionKeys {
    var initialInboundIV: [UInt8]

    var initialOutboundIV: [UInt8]

    var inboundEncryptionKey: SymmetricKey

    var outboundEncryptionKey: SymmetricKey

    var inboundMACKey: SymmetricKey

    var outboundMACKey: SymmetricKey
}

extension NIOSSHSessionKeys: Equatable {}

/// A helper structure that stores the expected key sizes for a key negotiation.
///
/// The key exchange result is transformed into keys by the application of a number of
/// hash function invocations. The output of these hash functions is truncated to an appropriate
/// length as needed, which means we need to ensure the code doing the calculation knows how
/// to truncate appropriately.
struct ExpectedKeySizes {
    var ivSize: Int

    var encryptionKeySize: Int

    var macKeySize: Int
}
