import XCTest
@testable import NIOSSH

final class Ed25519Tests: XCTestCase {

    func testInitFromRawSeedAndPublicKey_InvalidLengths_Throw() {
        // Too-short seed
        let shortSeed = Data(repeating: 1, count: 31)
        let pub = Data(repeating: 2, count: 32)
        XCTAssertThrowsError(try NIOSSHPrivateKey(ed25519PrivateKeySeed: shortSeed, publicKey: pub))

        // Too-short public key
        let seed = Data(repeating: 1, count: 32)
        let shortPub = Data(repeating: 2, count: 31)
        XCTAssertThrowsError(try NIOSSHPrivateKey(ed25519PrivateKeySeed: seed, publicKey: shortPub))
    }

    func testInitFromRawSeedAndPublicKey_NotImplementedYet_Throws() {
        // With valid lengths, the initializer is expected to throw until internal hookup is implemented.
        let seed = Data(repeating: 1, count: 32)
        let pub  = Data(repeating: 2, count: 32)
        XCTAssertThrowsError(try NIOSSHPrivateKey(ed25519PrivateKeySeed: seed, publicKey: pub))
    }

    func testDecodeOpenSSHPEM_SkippedUntilFixtureProvided() throws {
        throw XCTSkip("Add a known-good OpenSSH Ed25519 PEM fixture before enabling this test.")
    }
}
