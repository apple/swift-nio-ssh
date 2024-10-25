//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Benchmark
import NIOCore
import NIOEmbedded
import NIOSSH

let benchmarks = {
    let defaultMetrics: [BenchmarkMetric] = [
        .mallocCountTotal
    ]

    Benchmark(
        "OneCommandPerConnection",
        configuration: .init(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        try runOneCommandPerConnection(
            numberOfConnections: benchmark.scaledIterations.upperBound
        )
    }

    Benchmark(
        "StreamingLargeMessageInSmallChunks",
        configuration: .init(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        try runStreamingLargeMessageInSmallChunks(
            numberOfChunks: benchmark.scaledIterations.upperBound
        )
    }

    Benchmark(
        "ManySmallCommandsPerConnection",
        configuration: .init(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        try runManySmallCommandsPerConnection(
            numberOfWrites: benchmark.scaledIterations.upperBound
        )
    }
}
