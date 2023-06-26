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

/// A cryptographically secure random number generator.
///
/// SSH has a number of use-cases where we require a number of random bytes suitable
/// for use in cryptographic contexts. In this case, we want to defer to the system's
/// best available resource for these bytes. This object wraps those calls.
///
/// In an ideal world we'd be using something from Swift here, perhaps
/// `SystemRandomNumberGenerator`. However there is uncertainty about whether
/// `SystemRandomNumberGenerator` is actually suitable for use as a CSPRNG on all platforms:
/// see https://forums.swift.org/t/clarify-the-cryptographic-properties-of-systemrandomnumbergenerator/27249
/// for more details.
///
/// We feel confident that the `SystemRandomNumberGenerator` will remain a CSPRNG on all Apple platforms
/// and on Linux for the foreseeable future. This CSPRNG therefore wraps the `SystemRandomNumberGenerator`
/// on those platforms, and traps on all others.
struct CSPRNG: RandomNumberGenerator {
    private var baseRNG: SystemRandomNumberGenerator

    init() {
        #if canImport(Darwin) || os(Linux) || os(Android)
        self.baseRNG = SystemRandomNumberGenerator()
        #else
        fatalError("Platform does not have a supported CSPRNG")
        #endif
    }

    mutating func next() -> UInt64 {
        self.baseRNG.next()
    }
}
