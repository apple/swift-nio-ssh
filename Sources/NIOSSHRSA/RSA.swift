import NIO
import NIOFoundationCompat
import BigInt
import NIOSSH
import CCryptoBoringSSL
import Foundation
import Crypto

extension Insecure {
    public enum RSA {
        public enum Signing {}
    }
}

extension Insecure.RSA.Signing {
    public struct PublicKey: Equatable, Hashable, NIOSSHPublicKeyProtocol {
        public static let publicKeyPrefix = "ssh-rsa"
        
        // PublicExponent e
        private let publicExponent: BigUInt
        
        // Modulus n
        private let modulus: BigUInt
        
        public var rawRepresentation: Data {
            publicExponent.serialize() + modulus.serialize()
        }
        
        enum PubkeyParseError: Error {
            case invalidInitialSequence, invalidAlgorithmIdentifier, invalidSubjectPubkey, forbiddenTrailingData, invalidRSAPubkey
        }
        
        public init(publicExponent: BigUInt, modulus: BigUInt) {
            self.publicExponent = publicExponent
            self.modulus = modulus
        }
        
        public func encrypt<D: DataProtocol>(for message: D) throws -> EncrytpedMessage {
            let message = BigUInt(Data(message))
            
            guard message > .zero && message <= modulus - 1 else {
                throw RSAError.messageRepresentativeOutOfRange
            }
            
            let result = message.power(publicExponent, modulus: modulus)
            return EncrytpedMessage(rawRepresentation: result.serialize())
        }
        
        public func isValidSignature<D: DataProtocol>(_ signature: Signature, for digest: D) -> Bool {
            let signature = BigUInt(signature.rawRepresentation)
            
            guard signature > .zero && signature <= modulus - 1 else {
                return false
            }
            
            let m = signature.power(publicExponent, modulus: modulus)
            return m.serialize() == Data(digest)
        }
        
        public func isValidSignature<D>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool where D : DataProtocol {
            guard let signature = signature as? Signature else {
                return false
            }
            
            return isValidSignature(signature, for: data)
        }
        
        public func write(to buffer: inout ByteBuffer) -> Int {
            // For ssh-rsa, the format is public exponent `e` followed by modulus `n`
            var writtenBytes = 0
            writtenBytes += buffer.writeSSHString("ssh-rsa".utf8)
            writtenBytes += buffer.writePositiveMPInt(publicExponent.serialize())
            writtenBytes += buffer.writePositiveMPInt(modulus.serialize())
            return writtenBytes
        }
    }
    
    public struct EncrytpedMessage: ContiguousBytes {
        public let rawRepresentation: Data
        
        public init<D>(rawRepresentation: D) where D : DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try rawRepresentation.withUnsafeBytes(body)
        }
    }
    
    public struct Signature: ContiguousBytes, NIOSSHSignatureProtocol {
        public static let signaturePrefix = "ssh-rsa"
        
        public let rawRepresentation: Data
        
        public init<D>(rawRepresentation: D) where D : DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try rawRepresentation.withUnsafeBytes(body)
        }
        
        public func write(to buffer: inout ByteBuffer) -> Int {
            var writtenLength = buffer.writeSSHString(Self.signaturePrefix.utf8)

            // For SSH-RSA, the key format is the signature without lengths or paddings
            writtenLength += buffer.writeSSHString(rawRepresentation)
            
            return writtenLength
        }
    }
    
    public struct PrivateKey: NIOSSHPrivateKeyProtocol {
        public static let keyPrefix = "ssh-rsa"
        
        public enum Storage {
            case privateExponent(d: BigUInt, n: BigUInt)
            // TODO: Quintuple
        }
        
        // Private Exponent
        private let storage: Storage
        
        // Public Exponent e
        private let _publicKey: PublicKey
        
        public var publicKey: NIOSSHPublicKeyProtocol {
            _publicKey
        }
        
        public init(privateExponent: BigUInt, publicExponent: BigUInt, modulus: BigUInt) {
            self.storage = .privateExponent(d: privateExponent, n: modulus)
            self._publicKey = PublicKey(publicExponent: publicExponent, modulus: modulus)
        }
        
        public init(bits: Int = 2047, publicExponent e: BigUInt = 65537) {
            let p = BigUInt.randomPrime(bits: bits)
            let q = BigUInt.randomPrime(bits: bits)
            
            let n = p * q // modulus
            let phi = (p - 1) * (q - 1)
            let d = e.inverse(phi)!
            self.storage = .privateExponent(d: d, n: n)
               
            self._publicKey = PublicKey(
                publicExponent: e,
                modulus: n
            )
        }
        
        public func signature<D: DataProtocol>(for message: D) throws -> Signature {
            switch storage {
            case .privateExponent(_, let n):
                let message = try Self.encodePKCS1SHA1(message, length: (n.bitWidth + 7) / 8)
                
                let result = self.signature(for: BigUInt(Data(message)))
                return Signature(rawRepresentation: result.serialize())
            }
        }
        
        public func signature<D>(for data: D) throws -> NIOSSHSignatureProtocol where D : DataProtocol {
            return try self.signature(for: data) as Signature
        }
        
        private static func encodePKCS1SHA1<D: DataProtocol>(_ data: D, length: Int) throws -> Data {
            /*
             * This is the magic ASN.1/DER prefix that goes in the decoded
             * signature, between the string of FFs and the actual SHA-1
             * hash value. The meaning of it is:
             *
             * 00 -- this marks the end of the FFs; not part of the ASN.1
             * bit itself
             *
             * 30 21 -- a constructed SEQUENCE of length 0x21
             *    30 09 -- a constructed sub-SEQUENCE of length 9
             *       06 05 -- an object identifier, length 5
             *          2B 0E 03 02 1A -- object id { 1 3 14 3 2 26 }
             *                            (the 1,3 comes from 0x2B = 43 = 40*1+3)
             *       05 00 -- NULL
             *    04 14 -- a primitive OCTET STRING of length 0x14
             *       [0x14 bytes of hash data follows]
             *
             * The object id in the middle there is listed as `id-sha1' in
             * ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1d2.asn
             * (the ASN module for PKCS #1) and its expanded form is as
             * follows:
             *
             * id-sha1                OBJECT IDENTIFIER ::= {
             *    iso(1) identified-organization(3) oiw(14) secsig(3)
             *    algorithms(2) 26 }
             */
            let prefix: [UInt8] = [
                0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B,
                0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
            ]
            
            let padding = length - prefix.count - 2 - Insecure.SHA1.Digest.byteCount
            
            var buffer = ByteBuffer()
            buffer.writeInteger(0 as UInt8)
            buffer.writeInteger(1 as UInt8)
            for _ in 0..<padding {
                buffer.writeInteger(0xff as UInt8)
            }
            buffer.writeBytes(prefix)
            buffer.writeBytes(Insecure.SHA1.hash(data: data))
            
            return buffer.readData(length: buffer.readableBytes)!
        }
        
        private func signature(for m: BigUInt) -> BigUInt {
            switch storage {
            case let .privateExponent(d, n):
                return m.power(d, modulus: n)
            }
        }
        
        public func decrypt(_ signature: EncrytpedMessage) throws -> Data {
            let signature = BigUInt(signature.rawRepresentation)
            
            switch storage {
            case let .privateExponent(privateExponent, modulus):
                guard signature >= .zero && signature <= privateExponent else {
                    throw RSAError.ciphertextRepresentativeOutOfRange
                }
                
                return signature.power(privateExponent, modulus: modulus).serialize()
            }
        }
    }
}

public struct RSAError: Error {
    let message: String
    
    static let messageRepresentativeOutOfRange = RSAError(message: "message representative out of range")
    static let ciphertextRepresentativeOutOfRange = RSAError(message: "ciphertext representative out of range")
    static let signatureRepresentativeOutOfRange = RSAError(message: "signature representative out of range")
    static let invalidPem = RSAError(message: "invalid PEM")
    static let pkcs1Error = RSAError(message: "PKCS1Error")
}

extension BigUInt {
    public static func randomPrime(bits: Int) -> BigUInt {
        while true {
            var privateExponent = BigUInt.randomInteger(withExactWidth: bits)
            privateExponent |= 1
            
            if privateExponent.isPrime() {
                return privateExponent
            }
        }
    }
    
    fileprivate init(boringSSL bignum: UnsafeMutablePointer<BIGNUM>) {
        var data = [UInt8](repeating: 0, count: Int(CCryptoBoringSSL_BN_num_bytes(bignum)))
        CCryptoBoringSSL_BN_bn2bin(bignum, &data)
        self.init(Data(data))
    }
}

extension BigUInt {
    public static let diffieHellmanGroup14 = BigUInt(Data([
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ] as [UInt8]))
}

extension ByteBuffer {
    @discardableResult
    fileprivate mutating func writePositiveMPInt<Buffer: Collection>(_ value: Buffer) -> Int where Buffer.Element == UInt8 {
        // A positive MPInt must have its high bit set to zero, and not have leading zero bytes unless it needs that
        // high bit set to zero. We address this by dropping all the leading zero bytes in the collection first.
        let trimmed = value.drop(while: { $0 == 0 })
        let needsLeadingZero = ((trimmed.first ?? 0) & 0x80) == 0x80

        // Now we write the length.
        var writtenBytes: Int

        if needsLeadingZero {
            writtenBytes = self.writeInteger(UInt32(trimmed.count + 1))
            writtenBytes += self.writeInteger(UInt8(0))
        } else {
            writtenBytes = self.writeInteger(UInt32(trimmed.count))
        }

        writtenBytes += self.writeBytes(trimmed)
        return writtenBytes
    }
    
    /// Writes the given bytes as an SSH string at the writer index. Moves the writer index forward.
    @discardableResult
    mutating func writeSSHString<Buffer: Collection>(_ value: Buffer) -> Int where Buffer.Element == UInt8 {
        let writtenBytes = self.setSSHString(value, at: self.writerIndex)
        self.moveWriterIndex(forwardBy: writtenBytes)
        return writtenBytes
    }
    
    /// Sets the given bytes as an SSH string at the given offset. Does not mutate the writer index.
    @discardableResult
    mutating func setSSHString<Buffer: Collection>(_ value: Buffer, at offset: Int) -> Int where Buffer.Element == UInt8 {
        // RFC 4251 § 5:
        //
        // > Arbitrary length binary string.  Strings are allowed to contain
        // > arbitrary binary data, including null characters and 8-bit
        // > characters.  They are stored as a uint32 containing its length
        // > (number of bytes that follow) and zero (= empty string) or more
        // > bytes that are the value of the string.  Terminating null
        // > characters are not used.
        let lengthLength = self.setInteger(UInt32(value.count), at: offset)
        let valueLength = self.setBytes(value, at: offset + lengthLength)
        return lengthLength + valueLength
    }
    
    /// Sets the readable bytes of a ByteBuffer as an SSH string at the given offset. Does not mutate the writer index.
    @discardableResult
    mutating func setSSHString(_ value: ByteBuffer, at offset: Int) -> Int {
        // RFC 4251 § 5:
        //
        // > Arbitrary length binary string.  Strings are allowed to contain
        // > arbitrary binary data, including null characters and 8-bit
        // > characters.  They are stored as a uint32 containing its length
        // > (number of bytes that follow) and zero (= empty string) or more
        // > bytes that are the value of the string.  Terminating null
        // > characters are not used.
        let lengthLength = self.setInteger(UInt32(value.readableBytes), at: offset)
        let valueLength = self.setBuffer(value, at: offset + lengthLength)
        return lengthLength + valueLength
    }
}
