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

import Crypto
import NIOCore
@testable import NIOSSH
import XCTest

final class ByteBufferSSHTests: XCTestCase {
    func testGettingBoolFromByteBuffer() {
        var buffer = ByteBufferAllocator().buffer(capacity: 3)
        buffer.writeInteger(UInt8(0))
        buffer.writeInteger(UInt8(1))
        buffer.writeInteger(UInt8(62))

        XCTAssertFalse(buffer.getSSHBoolean(at: 0)!)
        XCTAssertTrue(buffer.getSSHBoolean(at: 1)!)
        XCTAssertTrue(buffer.getSSHBoolean(at: 2)!)
        XCTAssertNil(buffer.getSSHBoolean(at: 3))
    }

    func testReadingBoolFromByteBuffer() {
        var buffer = ByteBufferAllocator().buffer(capacity: 3)
        buffer.writeInteger(UInt8(0))
        buffer.writeInteger(UInt8(1))
        buffer.writeInteger(UInt8(62))

        XCTAssertFalse(buffer.readSSHBoolean()!)
        XCTAssertTrue(buffer.readSSHBoolean()!)
        XCTAssertTrue(buffer.readSSHBoolean()!)

        let previousReaderIndex = buffer.readerIndex
        XCTAssertNil(buffer.readSSHBoolean())
        XCTAssertEqual(buffer.readerIndex, previousReaderIndex)
    }

    func testGettingSSHStringFromByteBuffer() {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeBytes([0, 0, 0, 0]) // SSH empty string

        let helloWorldLength = 12
        buffer.writeInteger(UInt32(helloWorldLength))
        buffer.writeBytes("hello world!".utf8) // Simple utf8 string

        buffer.writeInteger(UInt32(5))
        buffer.writeRepeatingByte(0, count: 5) // All nulls string

        buffer.writeInteger(UInt32(5))
        buffer.writeRepeatingByte(42, count: 3) // Short string

        XCTAssertEqual(buffer.getSSHString(at: 0)?.array, [])
        XCTAssertEqual(buffer.getSSHString(at: 4)?.array, Array("hello world!".utf8))
        XCTAssertEqual(buffer.getSSHString(at: 4 + 4 + helloWorldLength)?.array, [0, 0, 0, 0, 0])
        XCTAssertNil(buffer.getSSHString(at: 4 + 4 + helloWorldLength + 4 + 5)) // String is short.

        buffer.clear()
        buffer.writeInteger(UInt16(5)) // Short length
        XCTAssertNil(buffer.getSSHString(at: 0))
    }

    func testReadingSSHStringFromByteBuffer() {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeBytes([0, 0, 0, 0]) // SSH empty string

        let helloWorldLength = 12
        buffer.writeInteger(UInt32(helloWorldLength))
        buffer.writeBytes("hello world!".utf8) // Simple utf8 string

        buffer.writeInteger(UInt32(5))
        buffer.writeRepeatingByte(0, count: 5) // All nulls string

        buffer.writeInteger(UInt32(5))
        buffer.writeRepeatingByte(42, count: 3) // Short string

        XCTAssertEqual(buffer.readSSHString()?.array, [])
        XCTAssertEqual(buffer.readSSHString()?.array, Array("hello world!".utf8))
        XCTAssertEqual(buffer.readSSHString()?.array, [0, 0, 0, 0, 0])

        var previousReaderIndex = buffer.readerIndex
        XCTAssertNil(buffer.readSSHString()) // String is short.
        XCTAssertEqual(buffer.readerIndex, previousReaderIndex)

        buffer.clear()
        buffer.writeInteger(UInt16(5)) // Short length

        previousReaderIndex = buffer.readerIndex
        XCTAssertNil(buffer.readSSHString())
        XCTAssertEqual(buffer.readerIndex, previousReaderIndex)
    }

    func testSettingSSHBoolInBuffer() {
        var buffer = ByteBufferAllocator().buffer(capacity: 0) // forcing some resizes as we go

        XCTAssertEqual(buffer.setSSHBoolean(false, at: 0), 1)
        XCTAssertEqual(buffer.setSSHBoolean(true, at: 1), 1)
        buffer.moveWriterIndex(forwardBy: 2)
        XCTAssertEqual(buffer.array, [0, 1])

        // Test we can overwrite safely.
        XCTAssertEqual(buffer.setSSHBoolean(true, at: 0), 1)
        XCTAssertEqual(buffer.setSSHBoolean(false, at: 1), 1)
        XCTAssertEqual(buffer.array, [1, 0])

        XCTAssertEqual(buffer.writeSSHBoolean(false), 1)
        XCTAssertEqual(buffer.writeSSHBoolean(true), 1)
        XCTAssertEqual(buffer.array, [1, 0, 0, 1])
    }

    func testSettingSSHStringInBufferWithCollection() {
        var buffer = ByteBufferAllocator().buffer(capacity: 0) // forcing some resizes as we go

        XCTAssertEqual(buffer.writeSSHString([UInt8]()), 4)
        XCTAssertEqual(buffer.array, [0, 0, 0, 0])

        XCTAssertEqual(buffer.setSSHString(repeatElement(5, count: 3), at: 1), 7)
        buffer.moveWriterIndex(forwardBy: 4)
        XCTAssertEqual(buffer.array, [0, 0, 0, 0, 3, 5, 5, 5])

        XCTAssertEqual(buffer.writeSSHString(CollectionOfOne(7)), 5)
        XCTAssertEqual(buffer.array, [0, 0, 0, 0, 3, 5, 5, 5, 0, 0, 0, 1, 7])
    }

    func testSettingSSHStringInBufferWithByteBuffer() {
        var sourceBuffer = ByteBufferAllocator().buffer(capacity: 12)
        sourceBuffer.writeBytes([5, 5, 5])
        var buffer = ByteBufferAllocator().buffer(capacity: 0) // forcing some resizes as we go

        var zeroBuffer = ByteBufferAllocator().buffer(capacity: 100)
        XCTAssertEqual(buffer.writeSSHString(&zeroBuffer), 4)
        XCTAssertEqual(buffer.array, [0, 0, 0, 0])

        XCTAssertEqual(buffer.setSSHString(sourceBuffer, at: 1), 7)
        buffer.moveWriterIndex(forwardBy: 4)
        XCTAssertEqual(buffer.array, [0, 0, 0, 0, 3, 5, 5, 5])

        XCTAssertEqual(buffer.writeSSHString(&sourceBuffer), 7)
        XCTAssertEqual(buffer.array, [0, 0, 0, 0, 3, 5, 5, 5, 0, 0, 0, 3, 5, 5, 5])
        XCTAssertEqual(sourceBuffer.readableBytes, 0)
    }

    func testWritingPaddingBytes() {
        // This only really tests that we write some padding bytes. We can't really validate randomness, so we
        // don't try.
        var buffer = ByteBufferAllocator().buffer(capacity: 100)
        var written = 0

        for i in 0 ..< 100 {
            written += buffer.writeSSHPaddingBytes(count: i)
            XCTAssertEqual(buffer.readerIndex, 0)
            XCTAssertEqual(buffer.writerIndex, written)
        }
    }

    func testWritePositiveMPInt() {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)

        // Test writing zero.
        XCTAssertEqual(buffer.writePositiveMPInt([]), 4)
        XCTAssertEqual(Array(buffer.readableBytesView), [0, 0, 0, 0])

        // Test writing with no leading zeros and top bit not set.
        buffer.clear()
        XCTAssertEqual(buffer.writePositiveMPInt([0x01, 0x02, 0x03, 0x04]), 8)
        XCTAssertEqual(Array(buffer.readableBytesView), [0, 0, 0, 4, 0x01, 0x02, 0x03, 0x04])

        // Test writing with no leading zeros and top bit set.
        buffer.clear()
        XCTAssertEqual(buffer.writePositiveMPInt([0x81, 0x02, 0x03, 0x04]), 9)
        XCTAssertEqual(Array(buffer.readableBytesView), [0, 0, 0, 5, 0, 0x81, 0x02, 0x03, 0x04])

        // Test writing with leading zeros and top bit not set.
        buffer.clear()
        XCTAssertEqual(buffer.writePositiveMPInt([0, 0, 0, 0, 1, 2, 3, 4]), 8)
        XCTAssertEqual(Array(buffer.readableBytesView), [0, 0, 0, 4, 1, 2, 3, 4])

        // Test writing with leading zeros and top bit set.
        buffer.clear()
        XCTAssertEqual(buffer.writePositiveMPInt([0, 0, 0, 0, 0x81, 0x02, 0x03, 0x04]), 9)
        XCTAssertEqual(Array(buffer.readableBytesView), [0, 0, 0, 5, 0, 0x81, 0x02, 0x03, 0x04])
    }

    func testWritingCompositeSSHString() {
        var buffer = ByteBufferAllocator().buffer(capacity: 100)

        let written = buffer.writeCompositeSSHString { buffer in
            var written = buffer.writeSSHString(Array("hello, world".utf8))
            written += buffer.writeSSHString(Array("goodbye, world".utf8))
            return written
        }

        XCTAssertEqual(written, 4 + 4 + 12 + 4 + 14)
        XCTAssertEqual(buffer.getInteger(at: buffer.readerIndex, as: UInt32.self), UInt32(written - 4))

        var stringPart = buffer.readSSHString()!
        let firstString = stringPart.readSSHString()
        let secondString = stringPart.readSSHString()

        // Check that everythign is empty.
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(stringPart.readableBytes, 0)

        XCTAssertEqual(firstString.map { Array($0.readableBytesView) }, Array("hello, world".utf8))
        XCTAssertEqual(secondString.map { Array($0.readableBytesView) }, Array("goodbye, world".utf8))
    }

    func testReadingEd25519SignaturesFromBuffers() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(ed25519Key: .init())
        let signature = try assertNoThrowWithValue(key.sign(digest: SHA256.hash(data: Array("hello, world!".utf8))))

        // Write a signature in.
        buffer.writeSSHSignature(signature)

        // Try reading short. This should always return nil, and never move the indices.
        for sliceLength in 0 ..< buffer.readableBytes {
            var slice = buffer.getSlice(at: buffer.readerIndex, length: sliceLength)!
            XCTAssertNoThrow(XCTAssertNil(try slice.readSSHSignature()))
            XCTAssertEqual(slice.readerIndex, 0)
            XCTAssertEqual(slice.writerIndex, sliceLength)
        }

        XCTAssertNoThrow(XCTAssertNotNil(try buffer.readSSHSignature()))
    }

    func testReadingECDSAP256SignaturesFromBuffers() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(p256Key: .init())
        let signature = try assertNoThrowWithValue(key.sign(digest: SHA256.hash(data: Array("hello, world!".utf8))))

        // Write a signature in.
        buffer.writeSSHSignature(signature)

        // Try reading short. This should always return nil, and never move the indices.
        for sliceLength in 0 ..< buffer.readableBytes {
            var slice = buffer.getSlice(at: buffer.readerIndex, length: sliceLength)!
            XCTAssertNoThrow(XCTAssertNil(try slice.readSSHSignature()))
            XCTAssertEqual(slice.readerIndex, 0)
            XCTAssertEqual(slice.writerIndex, sliceLength)
        }

        XCTAssertNoThrow(XCTAssertNotNil(try buffer.readSSHSignature()))
    }

    func testReadingECDSAP384SignaturesFromBuffers() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(p384Key: .init())
        let signature = try assertNoThrowWithValue(key.sign(digest: SHA384.hash(data: Array("hello, world!".utf8))))

        // Write a signature in.
        buffer.writeSSHSignature(signature)

        // Try reading short. This should always return nil, and never move the indices.
        for sliceLength in 0 ..< buffer.readableBytes {
            var slice = buffer.getSlice(at: buffer.readerIndex, length: sliceLength)!
            XCTAssertNoThrow(XCTAssertNil(try slice.readSSHSignature()))
            XCTAssertEqual(slice.readerIndex, 0)
            XCTAssertEqual(slice.writerIndex, sliceLength)
        }

        XCTAssertNoThrow(XCTAssertNotNil(try buffer.readSSHSignature()))
    }

    func testReadingECDSAP521SignaturesFromBuffers() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(p521Key: .init())
        let signature = try assertNoThrowWithValue(key.sign(digest: SHA512.hash(data: Array("hello, world!".utf8))))

        // Write a signature in.
        buffer.writeSSHSignature(signature)

        // Try reading short. This should always return nil, and never move the indices.
        for sliceLength in 0 ..< buffer.readableBytes {
            var slice = buffer.getSlice(at: buffer.readerIndex, length: sliceLength)!
            XCTAssertNoThrow(XCTAssertNil(try slice.readSSHSignature()))
            XCTAssertEqual(slice.readerIndex, 0)
            XCTAssertEqual(slice.writerIndex, sliceLength)
        }

        XCTAssertNoThrow(XCTAssertNotNil(try buffer.readSSHSignature()))
    }

    func testReadingEd25519PublicKeysFromBuffers() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(ed25519Key: .init())

        // Write a signature in.
        buffer.writeSSHHostKey(key.publicKey)

        // Try reading short. This should always return nil, and never move the indices.
        for sliceLength in 0 ..< buffer.readableBytes {
            var slice = buffer.getSlice(at: buffer.readerIndex, length: sliceLength)!
            XCTAssertNoThrow(XCTAssertNil(try slice.readSSHHostKey()))
            XCTAssertEqual(slice.readerIndex, 0)
            XCTAssertEqual(slice.writerIndex, sliceLength)
        }

        XCTAssertNoThrow(XCTAssertNotNil(try buffer.readSSHHostKey()))
    }

    func testReadingECDASAP256PublicKeysFromBuffers() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(p256Key: .init())

        // Write a signature in.
        buffer.writeSSHHostKey(key.publicKey)

        // Try reading short. This should always return nil, and never move the indices.
        for sliceLength in 0 ..< buffer.readableBytes {
            var slice = buffer.getSlice(at: buffer.readerIndex, length: sliceLength)!
            XCTAssertNoThrow(XCTAssertNil(try slice.readSSHHostKey()))
            XCTAssertEqual(slice.readerIndex, 0)
            XCTAssertEqual(slice.writerIndex, sliceLength)
        }

        XCTAssertNoThrow(XCTAssertNotNil(try buffer.readSSHHostKey()))
    }

    func testReadingECDASAP384PublicKeysFromBuffers() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(p384Key: .init())

        // Write a signature in.
        buffer.writeSSHHostKey(key.publicKey)

        // Try reading short. This should always return nil, and never move the indices.
        for sliceLength in 0 ..< buffer.readableBytes {
            var slice = buffer.getSlice(at: buffer.readerIndex, length: sliceLength)!
            XCTAssertNoThrow(XCTAssertNil(try slice.readSSHHostKey()))
            XCTAssertEqual(slice.readerIndex, 0)
            XCTAssertEqual(slice.writerIndex, sliceLength)
        }

        XCTAssertNoThrow(XCTAssertNotNil(try buffer.readSSHHostKey()))
    }

    func testReadingECDASAP521PublicKeysFromBuffers() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let key = NIOSSHPrivateKey(p521Key: .init())

        // Write a signature in.
        buffer.writeSSHHostKey(key.publicKey)

        // Try reading short. This should always return nil, and never move the indices.
        for sliceLength in 0 ..< buffer.readableBytes {
            var slice = buffer.getSlice(at: buffer.readerIndex, length: sliceLength)!
            XCTAssertNoThrow(XCTAssertNil(try slice.readSSHHostKey()))
            XCTAssertEqual(slice.readerIndex, 0)
            XCTAssertEqual(slice.writerIndex, sliceLength)
        }

        XCTAssertNoThrow(XCTAssertNotNil(try buffer.readSSHHostKey()))
    }
}

extension ByteBuffer {
    fileprivate var array: [UInt8] {
        self.getBytes(at: self.readerIndex, length: self.readableBytes)!
    }
}
