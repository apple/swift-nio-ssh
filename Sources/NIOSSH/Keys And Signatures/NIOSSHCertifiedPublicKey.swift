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

import Crypto
import Dispatch
import NIOCore
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Bionic)
import Bionic
#endif

/// A ``NIOSSHCertifiedPublicKey`` is an SSH public key combined with an SSH certificate.
///
/// SSH has a non-standard interface for using a very basic form of certificate-based authentication.
/// This is largely defined by OpenSSH, with the specification written down in [`PROTOCOL.certkeys`](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD) in the
/// OpenSSH repository.
///
/// These certificates are much simpler than X.509 certificates. They are less extensible and carry less
/// information. They cannot be "chained" in the same way as X.509 certificates (that is, the chain length is
/// essentially always 2, leaf + certificate authority). They are very specifically tied to the SSH protocol
/// and solve its specific problems.
///
/// Certificates are most often deployed in larger businesses where managing access control is important. In
/// particular, because the key certification can be done by a "certificate authority", it is possible to
/// tie certificate issuance into access control measures of various kinds. This is highly useful in large
/// enterprises.
///
/// In the SSH protocol itself, certificates fit into a slightly strange space. They are essentially a (weird)
/// key type on the wire, with more information available to them. To mirror this use-case, a ``NIOSSHCertifiedPublicKey``
/// is never directly passed to or from any of the interfaces in SwiftNIO SSH. Instead, it has an optional constructor
/// from ``NIOSSHPublicKey`` and ``NIOSSHPublicKey`` has a non-failing constructor from this key type. This allows users
/// to check at runtime whether a given ``NIOSSHPublicKey`` is _actually_ a ``NIOSSHCertifiedPublicKey``, and allows
/// users that have a ``NIOSSHCertifiedPublicKey`` to use it as though it were a ``NIOSSHPublicKey``.
public struct NIOSSHCertifiedPublicKey {
    /// The various key types that can be used with NIOSSHCertifiedPublicKey.
    internal enum SupportedKey: Hashable, Sendable {
        case ed25519(Curve25519.Signing.PublicKey)
        case ecdsaP256(P256.Signing.PublicKey)
        case ecdsaP384(P384.Signing.PublicKey)
        case ecdsaP521(P521.Signing.PublicKey)
        
        init(_ key: NIOSSHPublicKey) throws {
            switch key.backingKey {
            case let key as Curve25519.Signing.PublicKey:
                self = .ed25519(key)
            case let key as P256.Signing.PublicKey:
                self = .ecdsaP256(key)
            case let key as P384.Signing.PublicKey:
                self = .ecdsaP384(key)
            case let key as P521.Signing.PublicKey:
                self = .ecdsaP521(key)
            default:
                throw NIOSSHError.invalidCertificate(diagnostics: "Unsupported key type")
            }
        }

        var publicKey: NIOSSHPublicKeyProtocol {
            switch self {
            case .ed25519(let key):
                return key
            case .ecdsaP256(let key):
                return key
            case .ecdsaP384(let key):
                return key
            case .ecdsaP521(let key):
                return key
            }
        }

        public static func ==(lhs: SupportedKey, rhs: SupportedKey) -> Bool {
            switch (lhs, rhs) {
            case (.ed25519(let lhs), .ed25519(let rhs)):
                return lhs.rawRepresentation == rhs.rawRepresentation
            case (.ecdsaP256(let lhs), .ecdsaP256(let rhs)):
                return lhs.rawRepresentation == rhs.rawRepresentation
            case (.ecdsaP384(let lhs), .ecdsaP384(let rhs)):
                return lhs.rawRepresentation == rhs.rawRepresentation
            case (.ecdsaP521(let lhs), .ecdsaP521(let rhs)):
                return lhs.rawRepresentation == rhs.rawRepresentation
            default:
                return false
            }
        }

        public func hash(into hasher: inout Hasher) {
            switch self {
            case .ed25519(let key):
                hasher.combine(1)
                hasher.combine(key.rawRepresentation)
            case .ecdsaP256(let key):
                hasher.combine(2)
                hasher.combine(key.rawRepresentation)
            case .ecdsaP384(let key):
                hasher.combine(3)
                hasher.combine(key.rawRepresentation)
            case .ecdsaP521(let key):
                hasher.combine(4)
                hasher.combine(key.rawRepresentation)
            }
        }
    }

    /// A CA-provided random bitstring of arbitrary length (typically 16 or 32 bytes). This defends against
    /// hash-collision attacks.
    public var nonce: ByteBuffer {
        get {
            self.backing.nonce
        }
        set {
            self.ensureUniqueStorage()
            self.backing.nonce = newValue
        }
    }

    /// An optional certificate serial number set by the CA to refer to certificates from that CA. CAs are not
    /// required to number their certificates, and may set this field to zero if they wish.
    public var serial: UInt64 {
        get {
            self.backing.serial
        }
        set {
            self.ensureUniqueStorage()
            self.backing.serial = newValue
        }
    }

    /// The type of this certificate: what kind of role it authorises.
    public var type: CertificateType {
        get {
            self.backing.type
        }
        set {
            self.ensureUniqueStorage()
            self.backing.type = newValue
        }
    }

    /// The base public key associated with this certified public key.
    public var key: NIOSSHPublicKey {
        get {
            switch self.backing.key {
            case .ed25519(let key):
                return NIOSSHPublicKey(backingKey: key)
            case .ecdsaP256(let key):
                return NIOSSHPublicKey(backingKey: key)
            case .ecdsaP384(let key):
                return NIOSSHPublicKey(backingKey: key)
            case .ecdsaP521(let key):
                return NIOSSHPublicKey(backingKey: key)
            }
        }
        set {
            self.ensureUniqueStorage()
            self.backing.key = try! SupportedKey(newValue)
        }
    }

    /// A free-form text field filled in by the CA at the time of signing. Usually used to identify the identity
    /// principal.
    public var keyID: String {
        get {
            self.backing.keyID
        }
        set {
            self.ensureUniqueStorage()
            self.backing.keyID = newValue
        }
    }

    /// The principals for which this certified key is valid. For keys where ``NIOSSHCertifiedPublicKey/type``
    /// is ``NIOSSHCertifiedPublicKey/CertificateType/host``, these will be hostnames. For keys where
    /// ``NIOSSHCertifiedPublicKey/type`` is ``NIOSSHCertifiedPublicKey/CertificateType/user``, these will be
    /// usernames.
    ///
    /// If this is empty, the certificate is valid for _any_ principal of the given type.
    public var validPrincipals: [String] {
        get {
            self.backing.validPrincipals
        }
        set {
            self.ensureUniqueStorage()
            self.backing.validPrincipals = newValue
        }
    }

    /// The earliest instant for which this certificate is valid. The resolution of this field is in seconds since 1970-01-01
    /// 00:00:00.
    public var validAfter: UInt64 {
        get {
            self.backing.validAfter
        }
        set {
            self.ensureUniqueStorage()
            self.backing.validAfter = newValue
        }
    }

    /// The second after the latest instant for which this certificate is valid. The resolution of this field is in
    /// seconds since 1970-01-01 00:00:00.
    public var validBefore: UInt64 {
        get {
            self.backing.validBefore
        }
        set {
            self.ensureUniqueStorage()
            self.backing.validBefore = newValue
        }
    }

    /// Critical options are extensions that indicate restrictions on the default permissions of a certificate. These
    /// are most commonly used for certificates of ``NIOSSHCertifiedPublicKey/CertificateType/user`` type.
    ///
    /// These options are critical in the sense that critical options not recognised by an implementation must lead to the
    /// certificate being not trusted. SwiftNIO does not police these options itself, and relies on users to do so. The
    /// certificate validation APIs provide hooks to allow implementations to identify which options they are willing to
    /// police.
    ///
    /// The two critical options defined in the specification are only usable for
    /// ``NIOSSHCertifiedPublicKey/CertificateType/user`` certificates, and are:
    ///
    /// - `force-command`: Specifies a command that will be executed whenever this certificate is used for auth, replacing
    ///     anything the user selected.
    /// - `source-address`: A comma-separated list of valid source addresses for connections using this certificate. These will
    ///     be represented in CIDR format.
    public var criticalOptions: [String: String] {
        get {
            self.backing.criticalOptions
        }
        set {
            self.ensureUniqueStorage()
            self.backing.criticalOptions = newValue
        }
    }

    /// Extensions usually enable features that would otherwise be disabled for a given user. These are not critical: if they
    /// are not understood it is acceptable to ignore them. SwiftNIO does not act on any extensions: it is up to users to do so.
    public var extensions: [String: String] {
        get {
            self.backing.extensions
        }
        set {
            self.ensureUniqueStorage()
            self.backing.extensions = newValue
        }
    }

    /// The public key corresponding to the private key used to sign this ``NIOSSHCertifiedPublicKey``.
    public var signatureKey: NIOSSHPublicKey {
        get {
            NIOSSHPublicKey(backingKey: self.backing.signatureKey.publicKey)
        }
        set {
            self.ensureUniqueStorage()
            self.backing.signatureKey = try! SupportedKey(newValue)
        }
    }

    /// The signature over this certificate.
    public var signature: NIOSSHSignature {
        get {
            self.backing.signature
        }
        set {
            self.ensureUniqueStorage()
            self.backing.signature = newValue
        }
    }

    /// The class-based backing storage.
    private var backing: Backing

    public init(nonce: ByteBuffer,
                serial: UInt64,
                type: CertificateType,
                key: NIOSSHPublicKey,
                keyID: String,
                validPrincipals: [String],
                validAfter: UInt64,
                validBefore: UInt64,
                criticalOptions: [String: String],
                extensions: [String: String],
                signatureKey: NIOSSHPublicKey,
                signature: NIOSSHSignature) throws {
        self.backing = try Backing(nonce: nonce,
                                   serial: serial,
                                   type: type,
                                   key: SupportedKey(key),
                                   keyID: keyID,
                                   validPrincipals: validPrincipals,
                                   validAfter: validAfter,
                                   validBefore: validBefore,
                                   criticalOptions: criticalOptions,
                                   extensions: extensions,
                                   signatureKey: SupportedKey(signatureKey),
                                   signature: signature)
    }

    /// Attempt to unwrap a ``NIOSSHPublicKey`` that may contain a ``NIOSSHCertifiedPublicKey``.
    ///
    /// Not all public keys are certified, so this method will fail if the key is not.
    public init?(_ key: NIOSSHPublicKey) {
        guard let key = key.backingKey as? NIOSSHCertifiedPublicKey else {
            return nil
        }

        self = key
    }
}

// `NIOSSHCertifiedPublicKey` implements copy on write (CoW) and is therefore `Sendable`
extension NIOSSHCertifiedPublicKey: @unchecked Sendable {}

extension NIOSSHCertifiedPublicKey {
    /// Validates that a given certified public key is valid for usage.
    ///
    /// This function validates the following criteria:
    ///
    /// 1. Is the certificate attesting to an acceptable principal?
    /// 2. Is the certificate of the appropriate type?
    /// 3. Is the certificate within its valid duration?
    /// 4. Is the certificate signed by one of the `allowedAuthoritySigningKeys`?
    /// 5. Is the certificate attesting to any critical option that is not supported by this implementation?
    ///
    /// If all of the above tests pass, this function will return the values of the acceptable critical options.
    /// These values will not have been validated: validating them is the responsibility of the caller of this
    /// function, and failure to do so may lead to critical security flaws.
    ///
    /// If any of the above tests fail, this function will throw an error.
    ///
    /// - parameters:
    ///     - principal: The principal that this certificate must be attesting to. Either the
    ///         username the user asked for, or the hostname to which we connected.
    ///     - type: The type of certificate this must be.
    ///     - allowedAuthoritySigningKeys: The signing keys of the certificate authorities trusted by this
    ///         implementation.
    ///     - acceptableCriticalOptions: The critical options understood by this implementation that will be validated
    ///         separately from this function.
    /// - returns: The values of the supported critical options.
    /// - throws: If the certifiate fails to validate.
    public func validate(principal: String,
                         type: CertificateType,
                         allowedAuthoritySigningKeys: [NIOSSHPublicKey],
                         acceptableCriticalOptions: [String] = []) throws -> [String: String] {
        // Before we do any computation on values in this certificate, we first need to do the cryptographic
        // validation, to avoid the cryptographic doom principle. First, check if the signing key is in our allowed
        // set: second, validate the signature.
        guard allowedAuthoritySigningKeys.contains(self.signatureKey) else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Certificate was not signed by one of the allowed principals")
        }

        guard self.signatureKey.isValidSignature(self.signature, for: self.signableBytes) else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Signature is not valid for this certificate")
        }

        guard self.type == type else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Certificate is of unexpected type")
        }

        // There's a special case: no principals means valid for any principal
        guard self.validPrincipals.count == 0 || self.validPrincipals.contains(principal) else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Certificate is not valid for this principal")
        }

        // This can only be negative if we're in a terribly misconfigured system, so we can safely just turn this directly
        // into a UInt64.
        let now = DispatchWallTime.now()
        let validAfter = DispatchWallTime(secondsSinceEpoch: self.validAfter)
        let validBefore = DispatchWallTime(secondsSinceEpoch: self.validBefore)
        guard validAfter <= now, validBefore > now else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Certificate is no longer valid")
        }

        for criticalOption in self.criticalOptions.keys {
            guard acceptableCriticalOptions.contains(criticalOption) else {
                throw NIOSSHError.invalidCertificate(diagnostics: "Unsupported critical option present")
            }
        }

        return self.criticalOptions
    }

    internal var signableBytes: ByteBuffer {
        var bytes = ByteBufferAllocator().buffer(capacity: 2048)
        bytes.writeSignableBytes(self)
        return bytes
    }

    static let p256KeyPrefix = "ecdsa-sha2-nistp256-cert-v01@openssh.com"

    static let p384KeyPrefix = "ecdsa-sha2-nistp384-cert-v01@openssh.com"

    static let p521KeyPrefix = "ecdsa-sha2-nistp521-cert-v01@openssh.com"

    static let ed25519KeyPrefix = "ssh-ed25519-cert-v01@openssh.com"

    internal var keyPrefix: String.UTF8View {
        switch self.backing.key {
        case .ed25519:
            return Self.ed25519KeyPrefix.utf8
        case .ecdsaP256:
            return Self.p256KeyPrefix.utf8
        case .ecdsaP384:
            return Self.p384KeyPrefix.utf8
        case .ecdsaP521:
            return Self.p521KeyPrefix.utf8
        }
    }

    public func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignature, for data: D) -> Bool {
        self.key.isValidSignature(signature, for: data)
    }

    internal static func baseKeyPrefixForKeyPrefix<Bytes: Collection>(_ prefix: Bytes) throws -> String.UTF8View where Bytes.Element == UInt8 {
        if prefix.elementsEqual(Self.ed25519KeyPrefix.utf8) {
            return Curve25519.Signing.PublicKey.prefix.utf8
        } else if prefix.elementsEqual(Self.p256KeyPrefix.utf8) {
            return P256.Signing.PublicKey.prefix.utf8
        } else if prefix.elementsEqual(Self.p384KeyPrefix.utf8) {
            return P384.Signing.PublicKey.prefix.utf8
        } else if prefix.elementsEqual(Self.p521KeyPrefix.utf8) {
            return P521.Signing.PublicKey.prefix.utf8
        } else {
            throw NIOSSHError.unknownPublicKey(algorithm: String(decoding: prefix, as: UTF8.self))
        }
    }
}

extension NIOSSHCertifiedPublicKey: NIOSSHPublicKeyProtocol {
    public static var publicKeyPrefix: String? { nil }
    public var publicKeyPrefix: String { 
        switch self.backing.key {
        case .ed25519:
            return Self.ed25519KeyPrefix
        case .ecdsaP256:
            return Self.p256KeyPrefix
        case .ecdsaP384:
            return Self.p384KeyPrefix
        case .ecdsaP521:
            return Self.p521KeyPrefix
        }
    }
    public var rawRepresentation: Data { key.backingKey.rawRepresentation }

    public func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeCertifiedKey(self)
    }

    public func writeHostKey(to buffer: inout ByteBuffer) -> Int {
        buffer.writeCertifiedKey(self)
    }

    public static func read(from buffer: inout ByteBuffer) -> NIOSSHCertifiedPublicKey? {
        try? buffer.readCertifiedKey()
    }
}

extension NIOSSHCertifiedPublicKey: Hashable {}

extension NIOSSHCertifiedPublicKey: CustomDebugStringConvertible {
    public var debugDescription: String {
        """
        NIOSSHCertifiedPublicKey(
            nonce: \(self.nonce),
            serial: \(self.serial),
            type: \(self.type),
            key: \(self.key),
            keyID: \(self.keyID),
            validPrincipals: \(self.validPrincipals),
            validAfter: \(self.validAfter),
            validBefore: \(self.validBefore),
            criticalOptions: \(self.criticalOptions),
            extensions: \(self.extensions),
            signatureKey: \(self.signatureKey),
            signature: \(self.signature)
        )
        """.replacingOccurrences(of: "\n", with: "")
    }
}

extension NIOSSHCertifiedPublicKey {
    /// A ``NIOSSHCertifiedPublicKey/CertificateType`` defines the type of a given certificate.
    ///
    /// In SSH there are essentially two types in standard use: ``NIOSSHCertifiedPublicKey/CertificateType/user``
    /// and ``NIOSSHCertifiedPublicKey/CertificateType/host``. Certificates of type
    /// ``NIOSSHCertifiedPublicKey/CertificateType/user`` identify a user, while certificates of
    /// type ``NIOSSHCertifiedPublicKey/CertificateType/host`` identify a host.
    ///
    /// For extensibility purposes this is not defined as an enumeration, but instead as a `RawRepresentable` type
    /// wrapping the base type.
    public struct CertificateType: RawRepresentable, Sendable {
        public var rawValue: UInt32

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        /// A certificate valid for identifying a user.
        public static let user = CertificateType(rawValue: 1)

        /// A certificate valid for identifying a host.
        public static let host = CertificateType(rawValue: 2)
    }
}

extension NIOSSHCertifiedPublicKey.CertificateType: Hashable {}

extension NIOSSHCertifiedPublicKey.CertificateType: CustomStringConvertible {
    public var description: String {
        switch self {
        case .user:
            return "NIOSSHCertifiedPublicKey.CertificateType.user"
        case .host:
            return "NIOSSHCertifiedPublicKey.CertificateType.host"
        default:
            return "NIOSSHCertifiedPublicKey.CertificateType(rawValue: \(self.rawValue))"
        }
    }
}

extension NIOSSHCertifiedPublicKey {
    /// `NIOSSHCertifiedPublicKey` is a struct backed by a class. We do this for a few reasons:
    ///
    /// 1. The object is otherwise very large, 153 bytes! This is a lot of copying to do if it's passed
    ///     around: it'll inevitably get spilled to the stack each time.
    /// 2. The object contains 8 references, which is a lot. Each copy incurs 8 refcount operations, which is
    ///     way too high for copying this around by value.
    /// 3. This type would risk being self-referential. As this can be the backing type of a `NIOSSHPublicKey`,
    ///     but also _contains_ `NIOSSHPublicKey`s, at a certain point something must become an indirect type
    ///     in order to safely achieve that goal. Given that this type has decent performance reasons to want to
    ///     be heap-allocated, it may as well be this type that incurs that cost.
    ///
    /// By-and-large these objects aren't transient: they're created and used to verify a user or host, being passed through
    /// several methods including out through virtual method boundaries into user code. This more-than-justifies the allocation
    /// cost of creating them: heck, they need to allocate multiple times to be created for all their arrays and dictionaries.
    /// They are also very-rarely mutated: when they are, that mutation is done in the service of trying to actually build an
    /// SSH CA, and so the odds of them being uniquely owned are very high. Thus, the CoW costs are low.
    ///
    /// This all justifies moving this type into class-backed storage.
    fileprivate final class Backing {
        fileprivate var nonce: ByteBuffer
        fileprivate var serial: UInt64
        fileprivate var type: CertificateType
        fileprivate var key: SupportedKey

        fileprivate var keyID: String
        fileprivate var validPrincipals: [String]
        fileprivate var validAfter: UInt64
        fileprivate var validBefore: UInt64
        fileprivate var criticalOptions: [String: String]
        fileprivate var extensions: [String: String]
        fileprivate var signatureKey: SupportedKey

        fileprivate var signature: NIOSSHSignature

        fileprivate init(nonce: ByteBuffer,
                         serial: UInt64,
                         type: CertificateType,
                         key: SupportedKey,
                         keyID: String,
                         validPrincipals: [String],
                         validAfter: UInt64,
                         validBefore: UInt64,
                         criticalOptions: [String: String],
                         extensions: [String: String],
                         signatureKey: SupportedKey,
                         signature: NIOSSHSignature) throws {
            self.nonce = nonce
            self.serial = serial
            self.type = type
            self.key = key
            self.keyID = keyID
            self.validPrincipals = validPrincipals
            self.validAfter = validAfter
            self.validBefore = validBefore
            self.criticalOptions = criticalOptions
            self.extensions = extensions
            self.signatureKey = signatureKey
            self.signature = signature
        }

        fileprivate init(copying original: Backing) {
            self.nonce = original.nonce
            self.serial = original.serial
            self.type = original.type
            self.key = original.key
            self.keyID = original.keyID
            self.validPrincipals = original.validPrincipals
            self.validAfter = original.validAfter
            self.validBefore = original.validBefore
            self.criticalOptions = original.criticalOptions
            self.extensions = original.extensions
            self.signatureKey = original.signatureKey
            self.signature = original.signature
        }
    }

    /// Guarantees that the storage for this key is unique. Must be called before mutating anything on `.backing`.
    mutating func ensureUniqueStorage() {
        if !isKnownUniquelyReferenced(&self.backing) {
            self.backing = Backing(copying: self.backing)
        }
    }
}

extension NIOSSHCertifiedPublicKey.Backing: Hashable {
    static func == (lhs: NIOSSHCertifiedPublicKey.Backing, rhs: NIOSSHCertifiedPublicKey.Backing) -> Bool {
        (lhs.nonce == rhs.nonce &&
            lhs.serial == rhs.serial &&
            lhs.type == rhs.type &&
            lhs.key == rhs.key &&
            lhs.keyID == rhs.keyID &&
            lhs.validPrincipals == rhs.validPrincipals &&
            lhs.validAfter == rhs.validAfter &&
            lhs.validBefore == rhs.validBefore &&
            lhs.criticalOptions == rhs.criticalOptions &&
            lhs.extensions == rhs.extensions &&
            lhs.signatureKey == rhs.signatureKey &&
            lhs.signature == rhs.signature)
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(self.nonce)
        hasher.combine(self.serial)
        hasher.combine(self.type)
        hasher.combine(self.key)
        hasher.combine(self.keyID)
        hasher.combine(self.validPrincipals)
        hasher.combine(self.validAfter)
        hasher.combine(self.validBefore)
        hasher.combine(self.criticalOptions)
        hasher.combine(self.extensions)
        hasher.combine(self.signatureKey)
        hasher.combine(self.signature)
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeCertifiedKey(_ key: NIOSSHCertifiedPublicKey) -> Int {
        // A certified key is the signable bytes plus the signature.
        var written = 0
        written += self.writeSignableBytes(key)
        written += self.writeCompositeSSHString { buffer in
            buffer.writeSSHSignature(key.signature)
        }
        return written
    }

    @discardableResult
    fileprivate mutating func writeSignableBytes(_ key: NIOSSHCertifiedPublicKey) -> Int {
        var written = 0
        var nonceCopy = key.nonce
        written += self.writeSSHString(key.keyPrefix)
        written += self.writeSSHString(&nonceCopy)
        written += self.writePublicKeyWithoutPrefix(key.key)
        written += self.writeInteger(key.serial)
        written += self.writeInteger(key.type.rawValue)
        written += self.writeSSHString(key.keyID.utf8)
        written += self.writePrincipals(key.validPrincipals)
        written += self.writeInteger(key.validAfter)
        written += self.writeInteger(key.validBefore)
        written += self.writeMapStringString(key.criticalOptions)
        written += self.writeMapStringString(key.extensions)
        written += self.writeSSHString([]) // reserved
        written += self.writeCompositeSSHString { buffer in
            buffer.writeSSHHostKey(key.signatureKey)
        }
        return written
    }

    mutating func readCertifiedKey() throws -> NIOSSHCertifiedPublicKey? {
        try self.rewindOnNilOrError { `self` in
            guard let keyPrefix = self.readSSHStringAsString() else {
                return nil
            }

            return try self.readCertifiedKeyWithoutKeyPrefix(keyPrefix.utf8)
        }
    }

    mutating func readCertifiedKeyWithoutKeyPrefix<Bytes: Collection>(_ keyPrefix: Bytes) throws -> NIOSSHCertifiedPublicKey? where Bytes.Element == UInt8 {
        try self.rewindOnNilOrError { `self` in
            let innerKeyPrefix = try NIOSSHCertifiedPublicKey.baseKeyPrefixForKeyPrefix(keyPrefix)

            guard
                let nonce = self.readSSHString(),
                let key = try self.readPublicKeyWithoutPrefixForIdentifier(innerKeyPrefix),
                let serial = self.readInteger(as: UInt64.self),
                let rawType = self.readInteger(as: UInt32.self),
                let keyID = self.readSSHStringAsString(),
                var rawPrincipals = self.readSSHString(),
                let validAfter = self.readInteger(as: UInt64.self),
                let validBefore = self.readInteger(as: UInt64.self),
                var rawCriticalOptions = self.readSSHString(),
                var rawExtensions = self.readSSHString(),
                let _ = self.readSSHString(), // reserved
                var rawSignatureKey = self.readSSHString(),
                var rawSignature = self.readSSHString()
            else {
                return nil
            }

            guard
                let principals = rawPrincipals.readPrincipals(),
                let criticalOptions = try rawCriticalOptions.readMapStringToString(),
                let extensions = try rawExtensions.readMapStringToString(),
                let signatureKey = try rawSignatureKey.readSSHHostKey(),
                let signature = try rawSignature.readSSHSignature()
            else {
                throw NIOSSHError.invalidSSHMessage(reason: "invalid encoding of certified key")
            }

            return try NIOSSHCertifiedPublicKey(nonce: nonce,
                                                serial: serial,
                                                type: NIOSSHCertifiedPublicKey.CertificateType(rawValue: rawType),
                                                key: key,
                                                keyID: keyID,
                                                validPrincipals: principals,
                                                validAfter: validAfter,
                                                validBefore: validBefore,
                                                criticalOptions: criticalOptions,
                                                extensions: extensions,
                                                signatureKey: signatureKey,
                                                signature: signature)
        }
    }

    @discardableResult
    private mutating func writePrincipals(_ principals: [String]) -> Int {
        self.writeCompositeSSHString { buffer in
            var written = 0
            for principal in principals {
                written += buffer.writeSSHString(principal.utf8)
            }
            return written
        }
    }

    @discardableResult
    private mutating func writeMapStringString(_ map: [String: String]) -> Int {
        self.writeCompositeSSHString { buffer in
            var written = 0

            // Weird note: for these structures, the map needs to be lexicographically ordered by key. For
            // that reason we actually manifest this into an array and sort: it's cheaper than all the hashing.
            let namesAndValues = Array(map).sorted(by: { $0.key < $1.key })
            for entry in namesAndValues {
                written += buffer.writeSSHString(entry.key.utf8)

                if entry.value.utf8.count > 0 {
                    written += buffer.writeCompositeSSHString { $0.writeSSHString(entry.value.utf8) }
                } else {
                    written += buffer.writeInteger(UInt32(0)) // Empty SSH string
                }
            }
            return written
        }
    }

    private mutating func readPrincipals() -> [String]? {
        var principals = [String]()
        principals.reserveCapacity(1)

        while self.readableBytes > 0 {
            guard let nextPrincipal = self.readSSHStringAsString() else {
                return nil
            }
            principals.append(nextPrincipal)
        }

        return principals
    }

    private mutating func readMapStringToString() throws -> [String: String]? {
        var map: [String: String] = [:]

        while self.readableBytes > 0 {
            guard let key = self.readSSHStringAsString(), var valueString = self.readSSHString() else {
                return nil
            }
            // There's a weirdness here: if the value is non-empty, it's got a string _inside_ it. If it's
            // empty, it doesn't.
            let value: String
            if valueString.readableBytes > 0 {
                guard let innerString = valueString.readSSHStringAsString() else {
                    throw NIOSSHError.invalidSSHMessage(reason: "Invalid encoding of certificate map")
                }
                value = innerString
            } else {
                value = ""
            }
            map[key] = value
        }

        return map
    }
}

extension DispatchWallTime {
    init(secondsSinceEpoch: UInt64) {
        let t = timespec(tv_sec: time_t(secondsSinceEpoch), tv_nsec: 0)
        self = DispatchWallTime(timespec: t)
    }
}
