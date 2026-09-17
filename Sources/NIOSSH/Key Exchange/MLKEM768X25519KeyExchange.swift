//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import NIOFoundationCompat

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Post-quantum hybrid key exchange combining ML-KEM-768 (FIPS 203) with X25519.
///
/// Wire format and key derivation follow the IETF draft
/// `draft-kampanakis-curdle-ssh-pq-ke` and OpenSSH 9.9's
/// `mlkem768x25519-sha256` algorithm:
///
///   * Client init payload (single SSH string):
///       `MLKEM768 encapsulation key (1184 B) || X25519 public key (32 B)`
///   * Server reply payload (single SSH string):
///       `MLKEM768 ciphertext (1088 B) || X25519 public key (32 B)`
///   * Shared secret used by SSH:
///       `K = SHA-256(MLKEM_SS || X25519_SS)` — encoded as `mpint`
///   * Exchange-hash function: `SHA-256`
///
/// `K` is intentionally derived as a fixed-length SHA-256 digest so that an
/// attacker who compromises only one of the two primitives still cannot
/// recover the SSH session keys: ML-KEM contributes quantum resistance,
/// X25519 contributes well-studied classical security. This "hybrid by
/// hashing" matches OpenSSH 9.9.
///
/// > Important: This struct lazy-generates its ephemeral keypairs inside
/// > `initiateKeyExchangeClientSide(allocator:)` and
/// > `completeKeyExchangeServerSide(...)` because `MLKEM768.PrivateKey.init`
/// > can throw and the existing `EllipticCurveKeyExchangeProtocol.init`
/// > is neither throwing nor mutating. See the DRAFT PR description for the
/// > follow-up question of whether the protocol should grow a throwing
/// > variant or whether the lazy-generation pattern stays.
@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
struct MLKEM768X25519KeyExchange: EllipticCurveKeyExchangeProtocol {
    /// Size of an ML-KEM-768 encapsulation (public) key in bytes — FIPS 203 §8.
    static let mlkemPublicKeySize = 1184

    /// Size of an ML-KEM-768 ciphertext in bytes — FIPS 203 §8.
    static let mlkemCiphertextSize = 1088

    /// Size of an X25519 public key in bytes — RFC 7748 §6.1.
    static let x25519PublicKeySize = 32

    private var previousSessionIdentifier: ByteBuffer?
    private var ourRole: SSHConnectionRole

    // Client-only ephemeral state, populated during init.
    private var clientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var clientMLKEMPrivateKey: MLKEM768.PrivateKey?

    // Server-only ephemeral state, populated during completion.
    private var serverX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey?

    // SHA-256 digest of (MLKEM_SS || X25519_SS), held as raw bytes so it can
    // be fed into the SSH exchange hash as an `mpint`.
    private var sharedSecretDigest: [UInt8]?

    // Both payloads are echoed verbatim into the SSH exchange hash, so we
    // hold onto them across the init/reply round-trip.
    private var clientInitPayload: ByteBuffer?
    private var serverReplyPayload: ByteBuffer?

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.previousSessionIdentifier = previousSessionIdentifier
    }

    static var keyExchangeAlgorithmNames: [Substring] {
        ["mlkem768x25519-sha256"]
    }

    // MARK: - Client side

    mutating func initiateKeyExchangeClientSide(
        allocator: ByteBufferAllocator
    ) -> SSHMessage.KeyExchangeECDHInitMessage {
        precondition(self.ourRole.isClient, "Only clients may initiate the client side key exchange!")

        // ML-KEM-768 keygen is implemented as throwing in swift-crypto. The
        // KEX state machine doesn't tolerate a throwing initiator, so we
        // crash on the (theoretically unreachable) failure path. A future
        // protocol revision could make this method throwing.
        let x25519PrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let mlkemPrivateKey: MLKEM768.PrivateKey
        do {
            mlkemPrivateKey = try MLKEM768.PrivateKey()
        } catch {
            preconditionFailure("MLKEM768 keypair generation failed: \(error)")
        }

        self.clientX25519PrivateKey = x25519PrivateKey
        self.clientMLKEMPrivateKey = mlkemPrivateKey

        var payload = allocator.buffer(capacity: Self.mlkemPublicKeySize + Self.x25519PublicKeySize)
        payload.writeBytes(mlkemPrivateKey.publicKey.rawRepresentation)
        payload.writeBytes(x25519PrivateKey.publicKey.rawRepresentation)

        self.clientInitPayload = payload
        return .init(publicKey: payload)
    }

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage message: SSHMessage.KeyExchangeECDHReplyMessage,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult {
        precondition(self.ourRole.isClient, "Only clients may receive a server key exchange packet!")

        guard
            let clientX25519PrivateKey = self.clientX25519PrivateKey,
            let clientMLKEMPrivateKey = self.clientMLKEMPrivateKey,
            let clientInitPayload = self.clientInitPayload
        else {
            preconditionFailure("receiveServerKeyExchangePayload called before initiateKeyExchangeClientSide")
        }

        var replyBytes = message.publicKey
        guard replyBytes.readableBytes == Self.mlkemCiphertextSize + Self.x25519PublicKeySize else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        self.serverReplyPayload = replyBytes

        guard
            let mlkemCiphertext = replyBytes.readBytes(length: Self.mlkemCiphertextSize),
            let serverX25519PublicKeyBytes = replyBytes.readBytes(length: Self.x25519PublicKeySize)
        else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        let mlkemSharedSecret = try clientMLKEMPrivateKey.decapsulate(mlkemCiphertext)
        let serverX25519PublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: serverX25519PublicKeyBytes
        )
        let x25519SharedSecret = try clientX25519PrivateKey.sharedSecretFromKeyAgreement(
            with: serverX25519PublicKey
        )

        self.deriveHybridSharedSecret(
            mlkemSharedSecret: mlkemSharedSecret,
            x25519SharedSecret: x25519SharedSecret
        )

        let (kexResult, exchangeHash) = self.finalizeKeyExchange(
            clientInitPayload: clientInitPayload,
            serverReplyPayload: self.serverReplyPayload!,
            initialExchangeBytes: &initialExchangeBytes,
            serverHostKey: message.hostKey,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        guard message.hostKey.isValidSignature(message.signature, for: exchangeHash) else {
            throw NIOSSHError.invalidExchangeHashSignature
        }

        return kexResult
    }

    // MARK: - Server side

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: SSHMessage.KeyExchangeECDHInitMessage,
        serverHostKey: NIOSSHPrivateKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, SSHMessage.KeyExchangeECDHReplyMessage) {
        precondition(self.ourRole.isServer, "Only servers may receive a client key exchange packet!")

        var initBytes = message.publicKey
        guard initBytes.readableBytes == Self.mlkemPublicKeySize + Self.x25519PublicKeySize else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        self.clientInitPayload = initBytes

        guard
            let mlkemPublicKeyBytes = initBytes.readBytes(length: Self.mlkemPublicKeySize),
            let clientX25519PublicKeyBytes = initBytes.readBytes(length: Self.x25519PublicKeySize)
        else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        let serverX25519PrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self.serverX25519PrivateKey = serverX25519PrivateKey

        let mlkemPublicKey = try MLKEM768.PublicKey(rawRepresentation: mlkemPublicKeyBytes)
        let encapsulation = try mlkemPublicKey.encapsulate()
        let mlkemSharedSecret = encapsulation.sharedSecret
        let mlkemCiphertext = encapsulation.encapsulated

        let clientX25519PublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: clientX25519PublicKeyBytes
        )
        let x25519SharedSecret = try serverX25519PrivateKey.sharedSecretFromKeyAgreement(
            with: clientX25519PublicKey
        )

        self.deriveHybridSharedSecret(
            mlkemSharedSecret: mlkemSharedSecret,
            x25519SharedSecret: x25519SharedSecret
        )

        guard mlkemCiphertext.count == Self.mlkemCiphertextSize else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        var replyPayload = allocator.buffer(capacity: Self.mlkemCiphertextSize + Self.x25519PublicKeySize)
        replyPayload.writeBytes(mlkemCiphertext)
        replyPayload.writeBytes(serverX25519PrivateKey.publicKey.rawRepresentation)
        self.serverReplyPayload = replyPayload

        let (kexResult, exchangeHash) = self.finalizeKeyExchange(
            clientInitPayload: self.clientInitPayload!,
            serverReplyPayload: replyPayload,
            initialExchangeBytes: &initialExchangeBytes,
            serverHostKey: serverHostKey.publicKey,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        let exchangeHashSignature = try serverHostKey.sign(digest: exchangeHash)
        let responseMessage = SSHMessage.KeyExchangeECDHReplyMessage(
            hostKey: serverHostKey.publicKey,
            publicKey: replyPayload,
            signature: exchangeHashSignature
        )

        return (kexResult, responseMessage)
    }

    // MARK: - Hybrid secret derivation

    /// Folds the two component shared secrets into the SSH `K` value via
    /// `SHA-256(MLKEM_SS || X25519_SS)`. Per the IETF draft, fixed-length
    /// hashing prevents domain-separation issues and bounds `K` so subsequent
    /// SSH key derivation behaves identically to other SHA-256 KEX methods.
    private mutating func deriveHybridSharedSecret(
        mlkemSharedSecret: SymmetricKey,
        x25519SharedSecret: SharedSecret
    ) {
        var hasher = SHA256()
        mlkemSharedSecret.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        x25519SharedSecret.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        self.sharedSecretDigest = Array(hasher.finalize())
    }

    // MARK: - SSH exchange-hash + session-key derivation

    private func finalizeKeyExchange(
        clientInitPayload: ByteBuffer,
        serverReplyPayload: ByteBuffer,
        initialExchangeBytes: inout ByteBuffer,
        serverHostKey: NIOSSHPublicKey,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) -> (KeyExchangeResult, SHA256.Digest) {
        guard let sharedSecretDigest = self.sharedSecretDigest else {
            preconditionFailure("finalizeKeyExchange called before deriveHybridSharedSecret")
        }

        initialExchangeBytes.writeCompositeSSHString {
            $0.writeSSHHostKey(serverHostKey)
        }

        // Both client and server hash in payloads in the same canonical
        // order: client init then server reply. This matches the IETF
        // draft and how OpenSSH 9.9 computes the exchange hash.
        var initPayloadCopy = clientInitPayload
        var replyPayloadCopy = serverReplyPayload
        initialExchangeBytes.writeCompositeSSHString { $0.writeBuffer(&initPayloadCopy) }
        initialExchangeBytes.writeCompositeSSHString { $0.writeBuffer(&replyPayloadCopy) }

        var hasher = SHA256()
        hasher.update(data: initialExchangeBytes.readableBytesView)
        Self.updateAsMPInt(&hasher, sharedSecretDigest: sharedSecretDigest)

        let exchangeHash = hasher.finalize()

        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            var hashBytes = allocator.buffer(capacity: SHA256.Digest.byteCount)
            hashBytes.writeContiguousBytes(exchangeHash)
            sessionID = hashBytes
        }

        let keys = self.generateKeys(
            sharedSecretDigest: sharedSecretDigest,
            exchangeHash: exchangeHash,
            sessionID: sessionID,
            expectedKeySizes: expectedKeySizes
        )

        return (KeyExchangeResult(sessionID: sessionID, keys: keys), exchangeHash)
    }

    /// SSH's wire encoding for `K` is `mpint`: a length-prefixed big-endian
    /// two's-complement integer. For a 32-byte SHA-256 digest, we just need
    /// to insert a leading zero byte if the high bit is set so the value
    /// reads as positive. The 4-byte length prefix is also part of the
    /// hashed input per RFC 4253 §8.
    private static func updateAsMPInt(_ hasher: inout SHA256, sharedSecretDigest: [UInt8]) {
        let needsPadding = (sharedSecretDigest.first ?? 0) & 0x80 != 0
        let length = UInt32(sharedSecretDigest.count + (needsPadding ? 1 : 0))
        var lengthBE = length.bigEndian
        withUnsafeBytes(of: &lengthBE) { hasher.update(bufferPointer: $0) }
        if needsPadding {
            hasher.update(data: [UInt8(0)])
        }
        hasher.update(data: sharedSecretDigest)
    }

    /// Implements RFC 4253 §7.2 with `HASH = SHA-256`. Derives the six
    /// per-direction session keys (initial IVs, encryption keys, MAC keys)
    /// from `K`, `H` and the session identifier.
    private func generateKeys(
        sharedSecretDigest: [UInt8],
        exchangeHash: SHA256.Digest,
        sessionID: ByteBuffer,
        expectedKeySizes: ExpectedKeySizes
    ) -> NIOSSHSessionKeys {
        func deriveKey(letter: UInt8, expectedSize: Int) -> [UInt8] {
            // K1 = HASH(K || H || letter || session_id)
            var hasher = SHA256()
            Self.updateAsMPInt(&hasher, sharedSecretDigest: sharedSecretDigest)
            exchangeHash.withUnsafeBytes { hasher.update(bufferPointer: $0) }
            hasher.update(data: [letter])
            hasher.update(data: sessionID.readableBytesView)
            var out = Array(hasher.finalize())
            // K2 = HASH(K || H || K1); K3 = HASH(K || H || K1 || K2); ...
            while out.count < expectedSize {
                var extend = SHA256()
                Self.updateAsMPInt(&extend, sharedSecretDigest: sharedSecretDigest)
                exchangeHash.withUnsafeBytes { extend.update(bufferPointer: $0) }
                extend.update(data: out)
                out.append(contentsOf: extend.finalize())
            }
            return Array(out.prefix(expectedSize))
        }

        let ivCToS = deriveKey(letter: UInt8(ascii: "A"), expectedSize: expectedKeySizes.ivSize)
        let ivSToC = deriveKey(letter: UInt8(ascii: "B"), expectedSize: expectedKeySizes.ivSize)
        let encCToS = deriveKey(letter: UInt8(ascii: "C"), expectedSize: expectedKeySizes.encryptionKeySize)
        let encSToC = deriveKey(letter: UInt8(ascii: "D"), expectedSize: expectedKeySizes.encryptionKeySize)
        let macCToS = deriveKey(letter: UInt8(ascii: "E"), expectedSize: expectedKeySizes.macKeySize)
        let macSToC = deriveKey(letter: UInt8(ascii: "F"), expectedSize: expectedKeySizes.macKeySize)

        switch self.ourRole {
        case .client:
            return NIOSSHSessionKeys(
                initialInboundIV: ivSToC,
                initialOutboundIV: ivCToS,
                inboundEncryptionKey: SymmetricKey(data: encSToC),
                outboundEncryptionKey: SymmetricKey(data: encCToS),
                inboundMACKey: SymmetricKey(data: macSToC),
                outboundMACKey: SymmetricKey(data: macCToS)
            )
        case .server:
            return NIOSSHSessionKeys(
                initialInboundIV: ivCToS,
                initialOutboundIV: ivSToC,
                inboundEncryptionKey: SymmetricKey(data: encCToS),
                outboundEncryptionKey: SymmetricKey(data: encSToC),
                inboundMACKey: SymmetricKey(data: macCToS),
                outboundMACKey: SymmetricKey(data: macSToC)
            )
        }
    }
}
