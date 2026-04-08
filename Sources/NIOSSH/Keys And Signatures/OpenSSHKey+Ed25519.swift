import Foundation

public enum OpenSSHKey {
    public struct Ed25519Components {
        public let seed: Data     // 32 bytes
        public let publicKey: Data // 32 bytes
    }

    /// Decode an unencrypted OpenSSH Ed25519 private key (openssh-key-v1 format).
    /// - Parameter pem: The PEM text including BEGIN/END OPENSSH PRIVATE KEY markers.
    /// - Returns: Ed25519Components (seed + public key)
    /// - Throws: If the key is not in the expected format or is encrypted.
    public static func decodeEd25519Unencrypted(fromPEM pem: String) throws -> Ed25519Components {
        let header = "-----BEGIN OPENSSH PRIVATE KEY-----"
        let footer = "-----END OPENSSH PRIVATE KEY-----"
        let trimmed = pem.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.contains(header), trimmed.contains(footer) else {
            throw NIOSSHError.protocolViolation(protocolName: "openssh-key-v1", violation: "Not an OpenSSH private key")
        }

        let base64Body = trimmed
            .replacingOccurrences(of: header, with: "")
            .replacingOccurrences(of: footer, with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let blob = Data(base64Encoded: base64Body) else {
            throw NIOSSHError.protocolViolation(protocolName: "openssh-key-v1", violation: "Invalid base64 in OpenSSH private key")
        }

        var cursor = blob

        func readUInt32(_ data: inout Data) throws -> UInt32 {
            guard data.count >= 4 else { throw NIOSSHError.protocolViolation(protocolName: "openssh-key-v1", violation: "Truncated SSH string length") }
            let val = data.prefix(4)
            data.removeFirst(4)
            return val.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        }

        func readSSHString(_ data: inout Data) throws -> Data {
            let len = try readUInt32(&data)
            guard data.count >= Int(len) else { throw NIOSSHError.protocolViolation(protocolName: "openssh-key-v1", violation: "Truncated SSH string body") }
            let s = data.prefix(Int(len))
            data.removeFirst(Int(len))
            return s
        }

        // Verify magic
        let magic = "openssh-key-v1\0".data(using: .utf8)!
        guard cursor.prefix(magic.count) == magic else {
            throw NIOSSHError.protocolViolation(protocolName: "openssh-key-v1", violation: "Not openssh-key-v1 format")
        }
        cursor.removeFirst(magic.count)

        // ciphername, kdfname, kdfoptions
        let ciphername = try readSSHString(&cursor)
        let kdfname = try readSSHString(&cursor)
        _ = try readSSHString(&cursor) // kdfoptions

        guard String(data: ciphername, encoding: .utf8) == "none",
              String(data: kdfname, encoding: .utf8) == "none" else {
            throw NIOSSHError.protocolViolation(protocolName: "openssh-key-v1", violation: "Encrypted OpenSSH key not supported")
        }

        // number of keys
        let nkeys = try readUInt32(&cursor)
        guard nkeys == 1 else {
            throw NIOSSHError.protocolViolation(protocolName: "openssh-key-v1", violation: "Unexpected number of keys: \(nkeys)")
        }

        // public key blob (skip)
        _ = try readSSHString(&cursor)

        // private key section
        var priv = try readSSHString(&cursor)

        // two checkints
        _ = try readUInt32(&priv)
        _ = try readUInt32(&priv)

        // keytype
        let keyType = try readSSHString(&priv)
        guard String(data: keyType, encoding: .utf8) == "ssh-ed25519" else {
            throw NIOSSHError.protocolViolation(protocolName: "ssh-ed25519", violation: "Not an Ed25519 key")
        }

        // public key
        var pubKeyStr = try readSSHString(&priv)
        let pubRaw = try readSSHString(&pubKeyStr)
        guard pubRaw.count == 32 else {
            throw NIOSSHError.protocolViolation(protocolName: "ssh-ed25519", violation: "Invalid Ed25519 public key length \(pubRaw.count)")
        }

        // private key (64 bytes: 32 seed + 32 pub) as SSH string
        let privRaw = try readSSHString(&priv)
        guard privRaw.count == 64 else {
            throw NIOSSHError.protocolViolation(protocolName: "ssh-ed25519", violation: "Invalid Ed25519 private key length \(privRaw.count)")
        }

        let seed = privRaw.prefix(32)
        let pub = privRaw.suffix(32)

        return Ed25519Components(seed: Data(seed), publicKey: Data(pub))
    }
}
