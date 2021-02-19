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

protocol AcceptsVersionMessages {}

extension AcceptsVersionMessages {
    func receiveVersionMessage(_ banner: String, role: SSHConnectionRole) throws {
        try self.validateBanner(banner, role: role)
    }

    // From RFC 4253:
    //
    // > Protocol Version Exchange
    // >
    // > When the connection has been established, both sides MUST send an
    // > identification string.  This identification string MUST be
    // >   SSH-protoversion-softwareversion SP comments CR LF
    // > Since the protocol being defined in this set of documents is version
    // > 2.0, the 'protoversion' MUST be "2.0".  The 'comments' string is
    // > OPTIONAL.  If the 'comments' string is included, a 'space' character
    // > (denoted above as SP, ASCII 32) MUST separate the 'softwareversion'
    // > and 'comments' strings.  The identification MUST be terminated by a
    // > single Carriage Return (CR) and a single Line Feed (LF) character
    // > (ASCII 13 and 10, respectively).  Implementers who wish to maintain
    // > compatibility with older, undocumented versions of this protocol may
    // > want to process the identification string without expecting the
    // > presence of the carriage return character for reasons described in
    // > Section 5 of this document.  The null character MUST NOT be sent.
    // > The maximum length of the string is 255 characters, including the
    // > Carriage Return and Line Feed.
    // >
    // > The part of the identification string preceding the Carriage Return
    // > and Line Feed is used in the Diffie-Hellman key exchange (see Section
    // > 8).
    // >
    // > The server MAY send other lines of data before sending the version
    // > string.  Each line SHOULD be terminated by a Carriage Return and Line
    // > Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
    // > in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
    // > MUST be able to process such lines.  Such lines MAY be silently
    // > ignored, or MAY be displayed to the client user.  If they are
    // > displayed, control character filtering, as discussed in [SSH-ARCH],
    // > SHOULD be used.  The primary use of this feature is to allow TCP-
    // > wrappers to display an error message before disconnecting
    private func validateBanner(_ banner: String, role: SSHConnectionRole) throws {
        switch role {
        case .client:
            // split by \n
            let lineFeed = UInt8(ascii: "\n")
            for line in banner.utf8.split(separator: lineFeed) {
                if try self.validateVersion(line) {
                    return
                }
            }
            throw NIOSSHError.protocolViolation(protocolName: "version exchange", violation: "version string not found")
        case .server:
            guard try self.validateVersion(Substring(banner).utf8) else {
                throw NIOSSHError.protocolViolation(protocolName: "version exchange", violation: "version string not found")
            }
        }
    }

    private func validateVersion(_ version: Substring.UTF8View) throws -> Bool {
        if version.count > 7, version.starts(with: "SSH-".utf8) {
            let start = version.index(version.startIndex, offsetBy: 4)
            let end = version.index(start, offsetBy: 3)
            guard version[start ..< end].elementsEqual(Substring("2.0").utf8) else {
                throw NIOSSHError.unsupportedVersion(String(decoding: version, as: UTF8.self))
            }
            return true
        }
        return false
    }
}
