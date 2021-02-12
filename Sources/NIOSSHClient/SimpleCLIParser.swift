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

        // Let's start by searching for flags
        var listen: Listen?
        while let first = arguments.first, first.starts(with: "-") {
            arguments = arguments.dropFirst()

            switch first {
            case "-L":
                // The next argument is the listen string.
                guard let next = arguments.popFirst(), let parsed = Listen(listenString: next) else {
                    self.usage()
                }
                listen = parsed
            default:
                self.usage()
            }
        }

        // The first argument must be "target"
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

        return Result(commandString: command, target: targetURL, listen: listen)
    }

    private func usage() -> Never {
        print("NIOSSHClient [-L listenString] destination command...")
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

        var listen: Listen?

        fileprivate init(commandString: String?, target: URL, listen: Listen?) {
            self.commandString = commandString ?? "uname -a"
            self.host = target.host ?? "::1"
            self.port = target.port ?? 22
            self.user = target.user
            self.password = target.password
            self.listen = listen
        }
    }
}

extension SimpleCLIParser {
    // A structure representing a parsed listen string: [bind_address:]port:host:hostport
    struct Listen {
        var bindHost: Substring?
        var bindPort: Int
        var targetHost: Substring
        var targetPort: Int

        init?(listenString: String) {
            var components = listenString.split(separator: ":")

            switch components.count {
            case 4:
                self.bindHost = components.removeFirst()
                fallthrough
            case 3:
                guard let bindPort = Int(components.removeFirst()) else {
                    return nil
                }
                self.bindPort = bindPort
                self.targetHost = components.removeFirst()
                guard let targetPort = Int(components.removeFirst()) else {
                    return nil
                }
                self.targetPort = targetPort
            default:
                return nil
            }
        }
    }
}
