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
        Result()
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

        fileprivate init() {
            self.commandString = "yes \"long text\" | head -n 1000000\n"
            self.host = "localhost"
            self.port = 2223
            self.user = "username"
            self.password = "password"
            self.listen = nil
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
