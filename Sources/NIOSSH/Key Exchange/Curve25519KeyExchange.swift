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

import NIO
import NIOFoundationCompat
import CryptoKit


final class Curve25519KeyExchange {
    private var previousSessionIdentifier: ByteBuffer?
    private var ourKey: Curve25519.KeyAgreement.PrivateKey
    private var theirKey: Curve25519.KeyAgreement.PublicKey?
    private var ourRole: SSHConnectionRole
    private var sharedSecret: SharedSecret?

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.ourKey = Curve25519.KeyAgreement.PrivateKey()
        self.previousSessionIdentifier = previousSessionIdentifier
    }
}

extension Curve25519KeyExchange {
    /// Initiates key exchange by producing an SSH message.
    ///
    /// For now, we just return the ByteBuffer containing the SSH string.
    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> ByteBuffer {
        precondition(self.ourRole == .client, "Only clients may initiate the client side key exchange!")

        // The Curve25519 public key string size is 32 bytes.
        var buffer = allocator.buffer(capacity: 32)
        buffer.writeSSHString(self.ourKey.publicKey.rawRepresentation)
        return buffer
    }

    /// Handles receiving the client key exchange payload on the server side.
    ///
    /// - parameters:
    ///     - message: The received client key exchange message.
    ///     - serverHostKey: The host key belonging to this server.
    ///     - initialExchangeBytes: The initial bytes of the exchange, suitable for writing into the exchange hash.
    ///     - allocator: A `ByteBufferAllocator` suitable for this connection.
    ///     - expectedKeySizes: The sizes of the keys we need to generate.
    func completeKeyExchangeServerSide(clientKeyExchangeMessage message: ByteBuffer,
                                       serverHostKey: NIOSSHHostKey,
                                       initialExchangeBytes: inout ByteBuffer,
                                       allocator: ByteBufferAllocator,
                                       expectedKeySizes: ExpectedKeySizes) throws -> KeyExchangeResult {
        precondition(self.ourRole == .server, "Only servers may receive a client key exchange packet!")

        // The ECDH payload sent by the client is just the raw bytes of the public key as an SSH string.
        var message = message
        guard let keyBytes = message.readSSHString() else {
            throw NIOSSHError.invalidSSHMessage(reason: "Client Key Exchange with invalid internal length field")
        }

        // TODO: Build response message!
        return try self.finalizeKeyExchange(theirKeyBytes: keyBytes,
                                            initialExchangeBytes: &initialExchangeBytes,
                                            serverHostKey: serverHostKey,
                                            allocator: allocator,
                                            expectedKeySizes: expectedKeySizes)
    }

    /// Handles receiving the server key exchange payload on the client side.
    ///
    /// This function calculates the exchange hash and generates keys, and then verifies the exchange hash matches the server host key.
    ///
    /// - parameters:
    ///     - message: The received server key exchange message.
    ///     - initialExchangeBytes: The initial bytes of the exchange, suitable for writing into the exchange hash.
    ///     - allocator: A `ByteBufferAllocator` suitable for this connection.
    ///     - expectedKeySizes: The sizes of the keys we need to generate.
    func receiveServerKeyExchangePayload(serverKeyExchangeMessage message: ByteBuffer,
                                         initialExchangeBytes: inout ByteBuffer,
                                         allocator: ByteBufferAllocator,
                                         expectedKeySizes: ExpectedKeySizes) throws -> KeyExchangeResult {
        precondition(self.ourRole == .client, "Only clients may receive a server key exchange packet!")

        // Ok, we have a few steps here. Firstly, we need to parse the server key exchange message, extract the server's
        // public key, and generate our shared secret. Then we need to validate that we didn't generate a weak shared secret
        // (possible under some cases), as this must fail the key exchange process.
        //
        // With that done, we need to compute the exchange hash by appending the extra information we received from the
        // key exchange machinery. We then verify this hash using the server host key.
        //
        // Finally, we return our generated keys to the state machine.

        // The ECDH payload sent by the server is:
        //
        // > string   K_S, server's public host key
        // > string   Q_S, server's ephemeral public key octet string
        // > string   the signature on the exchange hash
        //
        // We need to parse these out.
        var message = message
        guard let serverHostKey = message.readSSHHostKey(),
              let serverEphemeralKeyBytes = message.readSSHString(),
              let exchangeHashSignature = message.readSSHString() else {
            throw NIOSSHError.invalidSSHMessage(reason: "Server Key Exchange with invalid internal length field")
        }

        // TODO: Verify signature on exchange hash.
        return try self.finalizeKeyExchange(theirKeyBytes: serverEphemeralKeyBytes,
                                            initialExchangeBytes: &initialExchangeBytes,
                                            serverHostKey: serverHostKey,
                                            allocator: allocator,
                                            expectedKeySizes: expectedKeySizes)
    }


    private func finalizeKeyExchange(theirKeyBytes: ByteBuffer,
                                     initialExchangeBytes: inout ByteBuffer,
                                     serverHostKey: NIOSSHHostKey,
                                     allocator: ByteBufferAllocator,
                                     expectedKeySizes: ExpectedKeySizes) throws -> KeyExchangeResult {
        self.theirKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirKeyBytes.readableBytesView)
        self.sharedSecret = try self.ourKey.sharedSecretFromKeyAgreement(with: self.theirKey!)
        guard self.sharedSecret!.isStrongSecret else {
            throw NIOSSHError.weakSharedSecret(exchangeAlgorithm: "Curve25519")
        }

        // Ok, we have a nice shared secret. Now we want to generate the exchange hash. We were given the initial
        // portion from the state machine: here we just need to append the Curve25519 parts. That is:
        //
        // - the public host key bytes
        // - the client public key octet string
        // - the server public key octet string
        // - the shared secret, as an mpint.
        initialExchangeBytes.writeSSHHostKey(serverHostKey)

        switch self.ourRole {
        case .client:
            initialExchangeBytes.writeSSHString(self.ourKey.publicKey.rawRepresentation)
            initialExchangeBytes.writeSSHString(self.theirKey!.rawRepresentation)
        case .server:
            initialExchangeBytes.writeSSHString(self.theirKey!.rawRepresentation)
            initialExchangeBytes.writeSSHString(self.ourKey.publicKey.rawRepresentation)
        }

        // Handling the shared secret is more awkward. We want to avoid putting the shared secret into unsecured
        // memory if we can, so rather than writing it into a bytebuffer, we'd like to hand it to CryptoKit directly
        // for signing. That means we need to set up our signing context.
        var hasher = SHA256()
        hasher.update(data: initialExchangeBytes.readableBytesView)

        // Finally, we update with the shared secret
        hasher.updateAsMPInt(sharedSecret: self.sharedSecret!)

        // Ok, now finalize the exchange hash. If we don't have a previous session identifier at this stage, we do now!
        let exchangeHash = hasher.finalize()
        var hashBytes = allocator.buffer(capacity: SHA256Digest.byteCount)
        hashBytes.writeBytes(exchangeHash)
        let sessionID = self.previousSessionIdentifier ?? hashBytes

        // Now we can generate the keys.
        let keys = self.generateKeys(sharedSecret: self.sharedSecret!, exchangeHash: hashBytes, sessionID: sessionID, expectedKeySizes: expectedKeySizes)

        return KeyExchangeResult(exchangeHash: hashBytes, keys: keys)
    }


    private func generateKeys(sharedSecret: SharedSecret, exchangeHash: ByteBuffer, sessionID: ByteBuffer, expectedKeySizes: ExpectedKeySizes) -> NIOSSHSessionKeys {
        // Cool, now it's time to generate the keys. In my ideal world I'd have a mechanism to handle this digest securely, but this is
        // not available in CryptoKit so we're going to spill these keys all over the heap and the stack. This isn't ideal, but I don't
        // think the risk is too bad.
        //
        // We generate these as follows:
        //
        // - Initial IV client to server: HASH(K || H || "A" || session_id)
        //    (Here K is encoded as mpint and "A" as byte and session_id as raw
        //    data.  "A" means the single character A, ASCII 65).
        // - Initial IV server to client: HASH(K || H || "B" || session_id)
        // - Encryption key client to server: HASH(K || H || "C" || session_id)
        // - Encryption key server to client: HASH(K || H || "D" || session_id)
        // - Integrity key client to server: HASH(K || H || "E" || session_id)
        // - Integrity key server to client: HASH(K || H || "F" || session_id)
        //
        // As all of these hashes begin the same way we save a trivial amount of compute by
        // using the value semantics of the hasher.
        var baseHasher = SHA256()
        baseHasher.updateAsMPInt(sharedSecret: sharedSecret)
        baseHasher.update(data: exchangeHash.readableBytesView)

        switch self.ourRole {
        case .client:
            return NIOSSHSessionKeys(initialInboundIV: self.generateServerToClientIV(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.ivSize),
                                     initialOutboundIV: self.generateClientToServerIV(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.ivSize),
                                     inboundEncryptionKey: self.generateServerToClientEncryptionKey(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.encryptionKeySize),
                                     outboundEncryptionKey: self.generateClientToServerEncryptionKey(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.encryptionKeySize),
                                     inboundMACKey: self.generateServerToClientMACKey(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.macKeySize),
                                     outboundMACKey: self.generateClientToServerMACKey(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.macKeySize))
        case .server:
            return NIOSSHSessionKeys(initialInboundIV: self.generateClientToServerIV(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.ivSize),
                                     initialOutboundIV: self.generateServerToClientIV(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.ivSize),
                                     inboundEncryptionKey: self.generateClientToServerEncryptionKey(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.encryptionKeySize),
                                     outboundEncryptionKey: self.generateServerToClientEncryptionKey(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.encryptionKeySize),
                                     inboundMACKey: self.generateClientToServerMACKey(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.macKeySize),
                                     outboundMACKey: self.generateServerToClientMACKey(baseHasher: baseHasher, sessionID: sessionID, expectedKeySize: expectedKeySizes.macKeySize))
        }

    }

    private func generateClientToServerIV(baseHasher: SHA256, sessionID: ByteBuffer, expectedKeySize: Int) -> [UInt8] {
        assert(expectedKeySize <= SHA256.Digest.byteCount)
        return Array(self.generateSpecificHash(baseHasher: baseHasher, discriminatorByte: UInt8(ascii: "A"), sessionID: sessionID).prefix(expectedKeySize))
    }

    private func generateServerToClientIV(baseHasher: SHA256, sessionID: ByteBuffer, expectedKeySize: Int) -> [UInt8] {
        assert(expectedKeySize <= SHA256.Digest.byteCount)
        return Array(self.generateSpecificHash(baseHasher: baseHasher, discriminatorByte: UInt8(ascii: "B"), sessionID: sessionID).prefix(expectedKeySize))
    }

    private func generateClientToServerEncryptionKey(baseHasher: SHA256, sessionID: ByteBuffer, expectedKeySize: Int) -> SymmetricKey {
        assert(expectedKeySize <= SHA256.Digest.byteCount)
        return SymmetricKey.truncatingDigest(self.generateSpecificHash(baseHasher: baseHasher, discriminatorByte: UInt8(ascii: "C"), sessionID: sessionID), length: expectedKeySize)
    }

    private func generateServerToClientEncryptionKey(baseHasher: SHA256, sessionID: ByteBuffer, expectedKeySize: Int) -> SymmetricKey {
        assert(expectedKeySize <= SHA256.Digest.byteCount)
        return SymmetricKey.truncatingDigest(self.generateSpecificHash(baseHasher: baseHasher, discriminatorByte: UInt8(ascii: "D"), sessionID: sessionID), length: expectedKeySize)
    }

    private func generateClientToServerMACKey(baseHasher: SHA256, sessionID: ByteBuffer, expectedKeySize: Int) -> SymmetricKey {
        assert(expectedKeySize <= SHA256.Digest.byteCount)
        return SymmetricKey.truncatingDigest(self.generateSpecificHash(baseHasher: baseHasher, discriminatorByte: UInt8(ascii: "E"), sessionID: sessionID), length: expectedKeySize)
    }

    private func generateServerToClientMACKey(baseHasher: SHA256, sessionID: ByteBuffer, expectedKeySize: Int) -> SymmetricKey {
        assert(expectedKeySize <= SHA256.Digest.byteCount)
        return SymmetricKey.truncatingDigest(self.generateSpecificHash(baseHasher: baseHasher, discriminatorByte: UInt8(ascii: "F"), sessionID: sessionID), length: expectedKeySize)
    }

    private func generateSpecificHash(baseHasher: SHA256, discriminatorByte: UInt8, sessionID: ByteBuffer) -> SHA256.Digest {
        var localHasher = baseHasher
        localHasher.update(byte: discriminatorByte)
        localHasher.update(data: sessionID.readableBytesView)
        return localHasher.finalize()
    }
}


extension SharedSecret {
    /// We need to check for the possibility that the peer's key is a point of low order.
    /// If it is, we will end up generating the all-zero shared secret, which is pretty not good.
    /// This property is `true` if the secret is strong, and `false` if it is not.
    fileprivate var isStrongSecret: Bool {
        // CryptoKit doesn't want to let us look directly at this, so we need to exfiltrate a pointer.
        // For the sake of avoiding leaking information about the secret, we choose to do this in constant
        // time by ORing every byte together: if the result is zero, this point is invalid.
        return self.withUnsafeBytes { dataPtr in
            let allORed = dataPtr.reduce(UInt8(0)) { $0 | $1 }
            return allORed != 0
        }
    }
}


extension SymmetricKey {
    /// Creates a symmetric key by truncating a given digest.
    fileprivate static func truncatingDigest(_ digest: SHA256Digest, length: Int) -> SymmetricKey {
        assert(length <= SHA256Digest.byteCount)
        return digest.withUnsafeBytes { bodyPtr in
            return SymmetricKey(data: UnsafeRawBufferPointer(rebasing: bodyPtr.prefix(length)))
        }
    }
}


extension SHA256 {
    fileprivate mutating func updateAsMPInt(sharedSecret: SharedSecret) {
        sharedSecret.withUnsafeBytes { secretBytesPtr in
            var secretBytesPtr = secretBytesPtr[...]

            // Here we treat this shared secret as an mpint by just treating these bytes as an unsigned
            // fixed-length integer in network byte order, as suggested by draft-ietf-curdle-ssh-curves-08,
            // and "prepending" it with a 32-bit length field. Note that instead of prepending, we just make
            // another call to update the hasher.
            //
            // Note that, as the integer is _unsigned_, it must be positive. That means we need to check the
            // top bit, because the SSH mpint format requires that the top bit only be set if the number is
            // negative. However, note that the SSH mpint format _also_ requires that we strip any leading
            // _unnecessary_ zero bytes. That means we have a small challenge.
            //
            // We address this by counting the number of zero bytes at the front of this pointer, and then
            // looking at the top bit of the _next_ byte. If the number of zero bytes at the front of this pointer
            // is 0, and the top bit of the next byte is 1, we hash an _extra_ zero byte before we hash the rest
            // of the body: we can put this zero byte into the buffer we've reserved for the length.
            //
            // If the number of zero bytes at the front of this pointer is more than 0, and the top bit of the
            // next byte is 1, we remove all but 1 of the zero bytes, and treat the rest as the body.
            //
            // Finally, if the number of zero bytes at the front of this pointer is more than 0, and the top
            // bit of the next byte is not 1, we remove all of the leading zero bytes, and treat the rest as the
            // body.
            guard let firstNonZeroByteIndex = secretBytesPtr.firstIndex(where: { $0 != 0 }) else {
                // Special case, this is the all zero secret. We shouldn't be able to hit this, as we check that this is a strong
                // secret above. Time to bail.
                preconditionFailure("Attempting to encode the all-zero secret as an mpint!")
            }
            let numberOfZeroBytes = firstNonZeroByteIndex - secretBytesPtr.startIndex
            let topBitOfFirstNonZeroByteIsSet = secretBytesPtr[firstNonZeroByteIndex] & 0x80 == 0x80

            // We need to hash a few extra bytes: specifically, we need a 4 byte length in network byte order,
            // and maybe a fifth as a zero byte.
            var lengthHelper = SharedSecretLengthHelper()

            switch (numberOfZeroBytes, topBitOfFirstNonZeroByteIsSet) {
            case (0, false):
                // This is the easy case, we just treat the whole thing as the body.
                lengthHelper.length = UInt8(secretBytesPtr.count)
                lengthHelper.useExtraZeroByte = false
            case (0, true):
                // This is an annoying case, we need to add a zero byte to the front.
                lengthHelper.length = UInt8(secretBytesPtr.count + 1)
                lengthHelper.useExtraZeroByte = true
            case (_, false):
                // Strip off all the leading zero bytes.
                secretBytesPtr = secretBytesPtr.dropFirst(numberOfZeroBytes)
                lengthHelper.length = UInt8(secretBytesPtr.count)
                lengthHelper.useExtraZeroByte = false
            case(_, true):
                // Strip off all but one of the leading zero bytes.
                secretBytesPtr = secretBytesPtr.dropFirst(numberOfZeroBytes - 1)
                lengthHelper.length = UInt8(secretBytesPtr.count)
                lengthHelper.useExtraZeroByte = false
            }

            // Now generate the hash.
            lengthHelper.update(hasher: &self)
            self.update(bufferPointer: UnsafeRawBufferPointer(rebasing: secretBytesPtr))
        }
    }

    /// A helper structure that allows us to hash in the extra bytes required to represent our shared secret as an mpint.
    ///
    /// An mpint is an SSH string, meaning that it is prefixed by a 4-byte length field. Additionally, in cases where the top
    /// bit of our shared secret is set (50% of the time), that length also needs to be followed by an extra zero bit. To
    /// avoid copying our shared secret into public memory, we fiddle about with those extra bytes in this structure, and
    /// pass an interior pointer to it into the hasher in order to give good hashing performance.
    private struct SharedSecretLengthHelper {
        // We need a 4 byte length in network byte order, and an optional fifth bit. As Curve25519 shared secrets are always
        // 32 bytes long (before the mpint transformation), we only ever actually need to modify one of these bytes:
        // the 4th.
        private var backingBytes = (UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0))

        /// Whether we should hash an extra zero byte.
        var useExtraZeroByte: Bool = false

        /// The length to encode.
        var length: UInt8 {
            get {
                return self.backingBytes.3
            }
            set {
                self.backingBytes.3 = newValue
            }
        }

        // Remove the elementwise initializer.
        init() { }

        func update(hasher: inout SHA256) {
            withUnsafeBytes(of: self.backingBytes) { bytesPtr in
                precondition(bytesPtr.count == 5)

                var bytesToHash: UnsafeRawBufferPointer
                if self.useExtraZeroByte {
                    bytesToHash = bytesPtr
                } else {
                    bytesToHash = UnsafeRawBufferPointer(rebasing: bytesPtr.prefix(4))
                }

                hasher.update(bufferPointer: bytesToHash)
            }
        }
    }
}


extension SHA256 {
    fileprivate mutating func update(byte: UInt8) {
        withUnsafeBytes(of: byte) { bytePtr in
            assert(bytePtr.count == 1, "Why is this 8 bit integer so large?")
            self.update(bufferPointer: bytePtr)
        }
    }
}
