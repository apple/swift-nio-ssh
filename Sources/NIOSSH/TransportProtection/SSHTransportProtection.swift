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

import NIOCore

/// A scheme that protects an SSH transport.
///
/// SSH supports a number of encryption schemes. These can be negotiated as part of the SSH handshake, and
/// when used they protect all SSH packets. These schemes vary widely in age and in the method by which they
/// are applied to SSH packets, and so rather than attempt to address them all we have decided to abstract
/// away the core of their function so that they may be implemented externally.
///
/// A `NIOSSHTransportProtection` implementation is a single object that must be able to perform both encryption
/// and integrity protection. For AEAD ciphers such as AES-GCM this is a single unified operation, but for non-AEAD
/// ciphers this may be split across two separate steps. This object is required to encapsulate both of them.
///
/// ### Key Exchange
///
/// This object does not perform key exchange, but is fed the results of key exchange operations. It is important that
/// implementers expect that the keys and IVs may change throughout the lifetime of a single connection, as SSH connections
/// will be re-keyed from time to time.
///
/// ### Negotiation
///
/// SSH technically negotiates the cipher and MAC separately, but in swift-nio-ssh we treat them as a single unified entity.
/// We do this because some implementations fundamentally tie these two operations together (e.g. AES GCM). This means that
/// implementations that support negotiating multiple MACs for the same cipher must expose multiple objects for the full set of
/// variants they support. In general this should be reasonably straightforward, though it does unfortunately rather increase the
/// size of the cipher/MAC lookup table.
///
/// ### Invariants
///
/// Implementers of this protocol **must not** expose unauthenticated plaintext, except for the length field. This
/// is required by the SSH protocol, and swift-nio-ssh does its best to treat the length field as fundamentally
/// untrusted information.
protocol NIOSSHTransportProtection: AnyObject {
    /// The name of the cipher portion of this transport protection scheme as negotiated on the wire.
    static var cipherName: String { get }

    /// The name of the MAC portion of this transport protection scheme as negotiated on the wire. May be nil, in which
    /// case this scheme does not care about the MAC field because it is an @openssh.org style AEAD construction.
    static var macName: String? { get }

    /// The block size of the cipher in this protection scheme.
    static var cipherBlockSize: Int { get }

    /// The key sizes required for this protection scheme.
    static var keySizes: ExpectedKeySizes { get }

    /// The number of bytes consumed by the MAC
    var macBytes: Int { get }

    /// Create a new instance of this transport protection scheme with the given keys.
    init(initialKeys: NIOSSHSessionKeys) throws

    /// A rekey has occurred and the encryption keys need to be changed.
    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws

    /// Given the first cipher block size, decrypt the length field.
    ///
    /// This function will be called whenever `source` has at least `cipherBlockSize` bytes
    /// available to read. The result of this call should be that the first four bytes of
    /// `source` now contain the plaintext length. The protection implementation is allowed to
    /// decrypt more if it chooses to, and may use the `source` buffer to store the result.
    ///
    /// It is guaranteed that `decryptRemainingPacket` will be called with exactly the same buffer
    /// passed to `source`. Thus some implementations will be able to avoid storing state for
    /// partial packet decryption.
    func decryptFirstBlock(_ source: inout ByteBuffer) throws

    /// Decrypt the remainder of the packet.
    ///
    /// This function will only be called once per call to `decryptFirstBlock`, and may not be
    /// called without a call to that. It is expected that this will decrypt the remaining data,
    /// return the packet body (i.e. the part of the packet that is not the length, the padding
    /// length, the padding, or the MAC), and update source to indicate the consumed bytes.
    /// It must also perform any integrity checking that
    /// is required and throw if the integrity check fails.
    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer) throws -> ByteBuffer

    /// Encrypt an entire outbound packet
    func encryptPacket(_ packet: NIOSSHEncryptablePayload, to outboundBuffer: inout ByteBuffer) throws
}

extension NIOSSHTransportProtection {
    /// Obtains the block size for this specific instantiated cipher.
    var cipherBlockSize: Int {
        // We just delegate to the static.
        Self.cipherBlockSize
    }
}
