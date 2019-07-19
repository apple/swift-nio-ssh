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

import NIO


extension ByteBuffer {
    /// Gets an SSH boolean field from a `ByteBuffer`.
    ///
    /// Returns the boolean value of the field, or `nil` if the index is not in the
    /// readable portion of the `ByteBuffer`.
    func getSSHBoolean(at offset: Int) -> Bool? {
        // RFC 4251 § 5:
        //
        // > A boolean value is stored as a single byte.  The value 0
        // > represents FALSE, and the value 1 represents TRUE.  All non-zero
        // > values MUST be interpreted as TRUE; however, applications MUST NOT
        // > store values other than 0 and 1.
        return self.getInteger(at: offset, as: UInt8.self).map { $0 != 0 }
    }

    /// Gets an SSH boolean field from a `ByteBuffer`, advancing the reader index.
    ///
    /// Returns the boolean value of the field, or `nil` if the index is not in the
    /// readable portion of the `ByteBuffer`.
    mutating func readSSHBoolean() -> Bool? {
        // RFC 4251 § 5:
        //
        // > A boolean value is stored as a single byte.  The value 0
        // > represents FALSE, and the value 1 represents TRUE.  All non-zero
        // > values MUST be interpreted as TRUE; however, applications MUST NOT
        // > store values other than 0 and 1.
        return self.readInteger(as: UInt8.self).map { $0 != 0 }
    }

    /// Gets the SSH binary string (byte sequence) stored at an offset in a `ByteBuffer`.
    ///
    /// Returns the slice of the `ByteBuffer` containing that byte sequence, assuming the buffer
    /// contains that many readable bytes at that offset. Returns `nil` otherwise.
    func getSSHString(at offset: Int) -> ByteBuffer? {
        // RFC 4251 § 5:
        //
        // > Arbitrary length binary string.  Strings are allowed to contain
        // > arbitrary binary data, including null characters and 8-bit
        // > characters.  They are stored as a uint32 containing its length
        // > (number of bytes that follow) and zero (= empty string) or more
        // > bytes that are the value of the string.  Terminating null
        // > characters are not used.
        guard let length = self.getInteger(at: offset, as: UInt32.self) else {
            return nil
        }

        return self.getSlice(at: offset + 4, length: Int(length))
    }

    /// Gets the SSH binary string (byte sequence) stored at an offset in a `ByteBuffer` and advances
    /// the reader index to consume the slice.
    ///
    /// Returns the slice of the `ByteBuffer` containing that byte sequence, assuming the buffer
    /// contains that many readable bytes at that offset. Returns `nil` otherwise.
    mutating func readSSHString() -> ByteBuffer? {
        guard let sshString = self.getSSHString(at: self.readerIndex) else {
            return nil
        }
        self.moveReaderIndex(forwardBy: sshString.readableBytes + 4)
        return sshString
    }
}
