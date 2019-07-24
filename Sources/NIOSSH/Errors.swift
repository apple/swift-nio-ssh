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


/// The errors that can be thrown by NIOSSH.
public struct NIOSSHError: Error {
    private var baseError: BaseError
}

extension NIOSSHError {
    private enum BaseError: Hashable {
        case invalidNonceLength
        case invalidEncryptedPacketLength
        case invalidDecryptedPlaintextLength
        case invalidKeySize
        case insufficientPadding
        case excessPadding
    }
}

extension NIOSSHError {
    /// The length of the nonce provided to a cipher is invalid for that cipher.
    public static let invalidNonceLength = NIOSSHError(baseError: .invalidNonceLength)

    /// The encrypted packet received has an invalid length for the negotiated encyption scheme
    public static let invalidEncryptedPacketLength = NIOSSHError(baseError: .invalidEncryptedPacketLength)

    /// The decrypted plaintext length is not a multiple of the block size.
    public static let invalidDecryptedPlaintextLength = NIOSSHError(baseError: .invalidDecryptedPlaintextLength)

    /// The generated key size was invalid for the given encryption scheme.
    public static let invalidKeySize = NIOSSHError(baseError: .invalidKeySize)

    /// A packet was decrypted that had insufficient padding.
    public static let insufficientPadding = NIOSSHError(baseError: .insufficientPadding)

    /// More padding bytes were supposed to be present than actually are present in a packet.
    public static let excessPadding = NIOSSHError(baseError: .excessPadding)
}

extension NIOSSHError: Hashable { }

extension NIOSSHError: CustomDebugStringConvertible {
    public var debugDescription: String {
        return String(describing: self.baseError)
    }
}
