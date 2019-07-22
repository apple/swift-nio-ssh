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

import CryptoKit


/// The result of a round of SSH key exchange.
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
struct NIOSSHKeyExchangeResult {
    var initialClientToServerIV: [UInt8]

    var initialServerToClientIV: [UInt8]

    var clientToServerEncryptionKey: SymmetricKey

    var serverToClientEncryptionKey: SymmetricKey

    var clientToServerMACKey: SymmetricKey

    var serverToClientMACKey: SymmetricKey
}
