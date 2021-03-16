// swift-tools-version:5.1
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "swift-nio-ssh",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        .library(name: "NIOSSH", targets: ["NIOSSH"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.27.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.0.0"),
    ],
    targets: [
        .target(name: "NIOSSH", dependencies: ["NIO", "NIOFoundationCompat", "Crypto"]),
        .target(name: "NIOSSHClient", dependencies: ["NIO", "NIOSSH", "NIOConcurrencyHelpers"]),
        .target(name: "NIOSSHServer", dependencies: ["NIO", "NIOSSH", "NIOFoundationCompat", "Crypto"]),
        .target(name: "NIOSSHPerformanceTester", dependencies: ["NIO", "NIOSSH", "Crypto"]),
        .testTarget(name: "NIOSSHTests", dependencies: ["NIOSSH", "NIO", "NIOFoundationCompat"]),
    ]
)
