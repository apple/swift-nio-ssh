//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftNIO project authors
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
        self.getInteger(at: offset, as: UInt8.self).map { $0 != 0 }
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
        self.readInteger(as: UInt8.self).map { $0 != 0 }
    }

    /// Writes an SSH boolean field from a `ByteBuffer`. Does not alter the writer index.
    @discardableResult
    mutating func setSSHBoolean(_ value: Bool, at index: Int) -> Int {
        // RFC 4251 § 5:
        //
        // > A boolean value is stored as a single byte.  The value 0
        // > represents FALSE, and the value 1 represents TRUE.  All non-zero
        // > values MUST be interpreted as TRUE; however, applications MUST NOT
        // > store values other than 0 and 1.
        let valueToWrite = value ? UInt8(1) : UInt8(0)
        return self.setInteger(valueToWrite, at: index)
    }

    /// Writes an SSH boolean field from a `ByteBuffer`, altering the writer index.
    @discardableResult
    mutating func writeSSHBoolean(_ value: Bool) -> Int {
        self.setSSHBoolean(value, at: self.writerIndex)
        self.moveWriterIndex(forwardBy: 1)
        return 1
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

    /// Sets the given bytes as an SSH string at the given offset. Does not mutate the writer index.
    @discardableResult
    mutating func setSSHString<Buffer: Collection>(_ value: Buffer, at offset: Int) -> Int where Buffer.Element == UInt8 {
        // RFC 4251 § 5:
        //
        // > Arbitrary length binary string.  Strings are allowed to contain
        // > arbitrary binary data, including null characters and 8-bit
        // > characters.  They are stored as a uint32 containing its length
        // > (number of bytes that follow) and zero (= empty string) or more
        // > bytes that are the value of the string.  Terminating null
        // > characters are not used.
        let lengthLength = self.setInteger(UInt32(value.count), at: offset)
        let valueLength = self.setBytes(value, at: offset + lengthLength)
        return lengthLength + valueLength
    }

    /// Writes the given bytes as an SSH string at the writer index. Moves the writer index forward.
    @discardableResult
    mutating func writeSSHString<Buffer: Collection>(_ value: Buffer) -> Int where Buffer.Element == UInt8 {
        let writtenBytes = self.setSSHString(value, at: self.writerIndex)
        self.moveWriterIndex(forwardBy: writtenBytes)
        return writtenBytes
    }

    /// Sets the readable bytes of a ByteBuffer as an SSH string at the given offset. Does not mutate the writer index.
    @discardableResult
    mutating func setSSHString(_ value: ByteBuffer, at offset: Int) -> Int {
        // RFC 4251 § 5:
        //
        // > Arbitrary length binary string.  Strings are allowed to contain
        // > arbitrary binary data, including null characters and 8-bit
        // > characters.  They are stored as a uint32 containing its length
        // > (number of bytes that follow) and zero (= empty string) or more
        // > bytes that are the value of the string.  Terminating null
        // > characters are not used.
        let lengthLength = self.setInteger(UInt32(value.readableBytes), at: offset)
        let valueLength = self.setBuffer(value, at: offset + lengthLength)
        return lengthLength + valueLength
    }

    /// Writes the readable bytes of a ByteBuffer as an SSH string at writer index. Moves the writer index forward.
    @discardableResult
    mutating func writeSSHString(_ value: inout ByteBuffer) -> Int {
        let writtenBytes = self.setSSHString(value, at: self.writerIndex)
        self.moveWriterIndex(forwardBy: writtenBytes)
        value.moveReaderIndex(to: value.writerIndex)
        return writtenBytes
    }

    @discardableResult
    mutating func writePositiveMPInt<Buffer: Collection>(_ value: Buffer) -> Int where Buffer.Element == UInt8 {
        // A positive MPInt must have its high bit set to zero, and not have leading zero bytes unless it needs that
        // high bit set to zero. We address this by dropping all the leading zero bytes in the collection first.
        let trimmed = value.drop(while: { $0 == 0 })
        let needsLeadingZero = ((trimmed.first ?? 0) & 0x80) == 0x80

        // Now we write the length.
        var writtenBytes: Int

        if needsLeadingZero {
            writtenBytes = self.writeInteger(UInt32(trimmed.count + 1))
            writtenBytes += self.writeInteger(UInt8(0))
        } else {
            writtenBytes = self.writeInteger(UInt32(trimmed.count))
        }

        writtenBytes += self.writeBytes(trimmed)
        return writtenBytes
    }

    /// Writes a given number of SSH-acceptable padding bytes to this buffer.
    @discardableResult
    public mutating func writeSSHPaddingBytes(count: Int) -> Int {
        // Annoyingly, the system random number generator can only give bytes to us 8 bytes at a time.
        precondition(count >= 0, "Cannot write negative number of padding bytes: \(count)")

        var rng = CSPRNG()
        var necessaryPaddingBytes = count

        while necessaryPaddingBytes > 0 {
            let writtenBytes: Int
            switch necessaryPaddingBytes {
            case 8...:
                writtenBytes = self.writeInteger(rng.next(), as: UInt64.self)
            case 4 ... 7:
                writtenBytes = self.writeInteger(rng.next(), as: UInt32.self)
            case 2 ... 3:
                writtenBytes = self.writeInteger(rng.next(), as: UInt16.self)
            case 1:
                writtenBytes = self.writeInteger(rng.next(), as: UInt8.self)
            default:
                preconditionFailure("Attempted to write negative number of bytes: \(necessaryPaddingBytes)")
            }

            necessaryPaddingBytes -= writtenBytes
        }

        precondition(necessaryPaddingBytes == 0, "Math is wrong, remaining expected padding bytes is nonzero: \(necessaryPaddingBytes)")
        return count
    }

    /// Many functions in SSH write composite data structures into an SSH string. This is a tricky thing to express
    /// without confining all of those functions to writing strings directly, which is pretty uncool. Instead, we can
    /// wrap the body into this function, which will take the returned total length and use that as the string length.
    @discardableResult
    mutating func writeCompositeSSHString(_ compositeFunction: (inout ByteBuffer) throws -> Int) rethrows -> Int {
        // Reserve 4 bytes for the length.
        let originalWriterIndex = self.writerIndex
        self.moveWriterIndex(forwardBy: 4)

        var writtenLength: Int
        do {
            writtenLength = try compositeFunction(&self)
        } catch {
            // Oops, it all went wrong, put the writer index back.
            self.moveWriterIndex(to: originalWriterIndex)
            throw error
        }

        // Ok, now we're going to write the length.
        writtenLength += self.setInteger(UInt32(writtenLength), at: originalWriterIndex)
        return writtenLength
    }

    /// A helper block that will rewind the reader index when an error is encountered.
    mutating func rewindReaderOnError<T>(_ body: (inout ByteBuffer) throws -> T) rethrows -> T {
        let oldReaderIndex = self.readerIndex

        do {
            return try body(&self)
        } catch {
            self.moveReaderIndex(to: oldReaderIndex)
            throw error
        }
    }

    /// A helper function that will rewind the reader index when nil is returned.
    mutating func rewindReaderOnNil<T>(_ body: (inout ByteBuffer) -> T?) -> T? {
        let oldReaderIndex = self.readerIndex

        guard let result = body(&self) else {
            self.moveReaderIndex(to: oldReaderIndex)
            return nil
        }

        return result
    }
}
