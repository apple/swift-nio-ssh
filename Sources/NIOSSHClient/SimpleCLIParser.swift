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
import Foundation

/// A very simple CLI parser.
struct SimpleCLIParser {
    func parse() -> Result {
        var arguments = CommandLine.arguments.dropFirst()

        // Right now we don't take flags, so the first argument must be "target"
        guard var target = arguments.popFirst() else {
            self.usage()
        }

        // We trick Foundation into doing something sensible here by prepending the target with ssh:// if it didn't
        // already have it.
        if !target.starts(with: "ssh://") {
            target = "ssh://" + target
        }

        guard let targetURL = URL(string: target) else {
            self.usage()
        }
        let command = arguments.joined(separator: " ")

        return Result(commandString: command, target: targetURL)
    }

    private func usage() -> Never {
        print("NIOSSHClient destination command...")
        exit(1)
    }
}

extension SimpleCLIParser {
    struct Result {
        var commandString: String

        var host: String

        var port: Int

        var user: String?

        var password: String?

        fileprivate init(commandString: String?, target: URL) {
            self.commandString = commandString ?? "uname -a"
            self.host = target.host ?? "::1"
            self.port = target.port ?? 22
            self.user = target.user
            self.password = target.password
        }
    }
}
