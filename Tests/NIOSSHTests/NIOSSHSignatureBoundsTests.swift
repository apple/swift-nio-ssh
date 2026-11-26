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

import NIOCore
import Testing

@testable import NIOSSH

struct NIOSSHSignatureBoundsTests {
    enum Curve: CaseIterable, Sendable {
        case p256, p384, p521

        var identifier: String {
            switch self {
            case .p256: "ecdsa-sha2-nistp256"
            case .p384: "ecdsa-sha2-nistp384"
            case .p521: "ecdsa-sha2-nistp521"
            }
        }

        var width: Int {
            switch self {
            case .p256: 32
            case .p384: 48
            case .p521: 66
            }
        }
    }

    @Test(arguments: Curve.allCases, [false, true])
    func oversizedComponentsAreRejected(curve: Curve, oversizedR: Bool) throws {
        // CHANGE: Exercise every curve and both components after optional SSH sign-padding removal.
        for length in [curve.width + 1, 4096] {
            for signPadded in [false, true] {
                let oversized = (signPadded ? [UInt8(0)] : []) + Array(repeating: UInt8(0x01), count: length)
                let ordinary = Array(repeating: UInt8(0x02), count: curve.width)
                var buffer = signatureBuffer(
                    curve: curve,
                    r: oversizedR ? oversized : ordinary,
                    s: oversizedR ? ordinary : oversized
                )
                let original = buffer

                #expect(throws: (any Error).self) {
                    do {
                        _ = try buffer.readSSHSignature()
                    } catch {
                        #expect((error as? NIOSSHError)?.type == .invalidSSHMessage)
                        throw error
                    }
                }
                #expect(buffer == original)
            }
        }
    }

    @Test(arguments: Curve.allCases, [false, true])
    func ordinaryComponentsRoundTrip(curve: Curve, signPadded: Bool) throws {
        // CHANGE: The bounds check must preserve full-width positive mpints and required sign padding.
        let component =
            (signPadded ? [UInt8(0), 0x80] : [UInt8(0x01)])
            + Array(repeating: UInt8(0x02), count: curve.width - 1)
        var buffer = signatureBuffer(curve: curve, r: component, s: component)
        let original = buffer
        let decoded = try buffer.readSSHSignature()
        let signature = try #require(decoded)
        #expect(buffer.readableBytes == 0)

        var encoded = ByteBufferAllocator().buffer(capacity: original.readableBytes)
        encoded.writeSSHSignature(signature)
        #expect(encoded == original)
    }

    private func signatureBuffer(curve: Curve, r: [UInt8], s: [UInt8]) -> ByteBuffer {
        var components = ByteBufferAllocator().buffer(capacity: r.count + s.count + 8)
        components.writeSSHString(r)
        components.writeSSHString(s)
        var buffer = ByteBufferAllocator().buffer(capacity: components.readableBytes + 32)
        buffer.writeSSHString(Array(curve.identifier.utf8))
        buffer.writeSSHString(&components)
        return buffer
    }
}
