import Foundation
import NIO

public protocol NIOSSHSignatureProtocol {
    static var signaturePrefix: String { get }
    var rawRepresentation: Data { get }
    
    func write(to buffer: inout ByteBuffer) -> Int
    
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

internal extension NIOSSHSignatureProtocol {
    var signaturePrefix: String {
        Self.signaturePrefix
    }
}

public protocol NIOSSHPublicKeyProtocol {
    static var publicKeyPrefix: String { get }
    var rawRepresentation: Data { get }
    
    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool
    
    func write(to buffer: inout ByteBuffer) -> Int
    
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

internal extension NIOSSHPublicKeyProtocol {
    var publicKeyPrefix: String {
        Self.publicKeyPrefix
    }
}

public protocol NIOSSHPrivateKeyProtocol {
    static var keyPrefix: String { get }
//    var rawRepresentation: Data { get }
    var publicKey: NIOSSHPublicKeyProtocol { get }
    
    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol
}

internal extension NIOSSHPrivateKeyProtocol {
    var keyPrefix: String {
        Self.keyPrefix
    }
}
