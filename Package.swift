// swift-tools-version:5.0
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
    products: [
        .library(name: "NIOSSH", targets: ["NIOSSH"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.4.0"),
    ],
    targets: [
        .target(name: "NIOSSH", dependencies: ["NIO"]),
        .testTarget(name: "NIOSSHTests", dependencies: ["NIOSSH", "NIO"]),
    ]
)

