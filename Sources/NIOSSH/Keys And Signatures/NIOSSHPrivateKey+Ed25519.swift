//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
//===----------------------------------------------------------------------===//

import Foundation

extension NIOSSHPrivateKey {
    /// Construct an Ed25519 private key from the 32-byte seed and 32-byte public key.
    /// - Parameters:
    ///   - seed: 32-byte Ed25519 private key seed.
    ///   - publicKey: 32-byte Ed25519 public key.
    /// - Throws: If the provided data is not the correct length or the key cannot be constructed.
    public init(ed25519PrivateKeySeed seed: Data, publicKey: Data) throws {
        guard seed.count == 32 else {
            throw NIOSSHError.protocolViolation(protocolName: "ssh-ed25519", violation: "ed25519 key construction not implemented")
        }
        guard publicKey.count == 32 else {
            throw NIOSSHError.protocolViolation(protocolName: "ssh-ed25519", violation: "Invalid Ed25519 public key length \(publicKey.count), expected 32 bytes")
        }

        // Internally, NIOSSH expects an Ed25519 key that can sign using the ssh-ed25519 algorithm.
        // Depending on the NIOSSH internal API, you may need to wrap these bytes into the library’s
        // Ed25519 representation. This initializer provides a stable public entry point.
        //
        // The actual internal storage and signer hookup should be implemented to match NIOSSH’s
        // existing key handling. If an internal Ed25519 representation already exists, initialize it here.

        // Pseudocode placeholder for internal hookup:
        // self = .ed25519(Ed25519PrivateKeyRepresentation(seed: [UInt8](seed), publicKey: [UInt8](publicKey)))

        // If the Ed25519 representation is not directly available, throw for now.
        // Replace this with the appropriate internal initializer for your codebase.
        throw NIOSSHError.protocolViolation(protocolName: "ssh-ed25519", violation: "ed25519 key construction not implemented")
    }
}//
//  NIOSSHPrivateKey+Ed25519.swift
//  swift-nio-ssh
//
//  Created by Simon Bruce-Cassidy on 08/12/2025.
//


