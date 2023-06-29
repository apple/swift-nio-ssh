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

import NIOCore

struct SSHPacketSerializer {
    enum State {
        case initialized
        case cleartext
        case encrypted(NIOSSHTransportProtection)
    }

    private var state: State = .initialized
    private(set) var sequenceNumber: UInt32 = 0

    /// Encryption schemes can be added to a packet serializer whenever encryption is negotiated.
    mutating func addEncryption(_ protection: NIOSSHTransportProtection) {
        switch self.state {
        case .cleartext:
            self.state = .encrypted(protection)
        case .encrypted:
            self.state = .encrypted(protection)
        case .initialized:
            preconditionFailure("Adding encryption in invalid state: \(self.state)")
        }
    }

    mutating func serialize(message: SSHMessage, to buffer: inout ByteBuffer) throws {
        switch self.state {
        case .initialized:
            switch message {
            case .version:
                buffer.writeSSHMessage(message)
                self.state = .cleartext
            default:
                preconditionFailure("only .version message is allowed at this point")
            }
        case .cleartext:
            buffer.writeSSHPacket(message: message, lengthEncrypted: true, blockSize: 8)
            self.sequenceNumber &+= 1
        case .encrypted(let protection):
            let index = buffer.readerIndex
            buffer.moveReaderIndex(to: buffer.writerIndex)
            buffer.writeSSHPacket(message: message, lengthEncrypted: protection.lengthEncrypted, blockSize: protection.cipherBlockSize)
            try protection.encryptPacket(&buffer, sequenceNumber: self.sequenceNumber)
            buffer.moveReaderIndex(to: index)
            self.sequenceNumber &+= 1
        }
    }
}

extension ByteBuffer {
    mutating func writeSSHPacket(message: SSHMessage, lengthEncrypted: Bool, blockSize: Int) {
        let index = self.writerIndex

        /// Each packet is in the following format:
        ///
        ///   uint32        packet_length
        ///   byte           padding_length
        ///   byte[n1]  payload; n1 = packet_length - padding_length - 1
        ///   byte[n2]  random padding; n2 = padding_length
        ///   byte[m]   mac (Message Authentication Code - MAC); m = mac_length

        /// payload
        self.writeMultipleIntegers(UInt32(0), UInt8(0))
        let messageLength = self.writeSSHMessage(message)

        // Depending on on whether packet length is encrypted, padding should reflect that
        let payloadLength = lengthEncrypted ? messageLength + 5 : messageLength + 1

        /// RFC 4253 § 6:
        /// random padding
        ///   Arbitrary-length padding, such that the total length of (packet_length || padding_length || payload || random padding)
        ///   is a multiple of the cipher block size or 8, whichever is larger.  There MUST be at least four bytes of padding.  The
        ///   padding SHOULD consist of random bytes.  The maximum amount of padding is 255 bytes.
        var paddingLength = blockSize - (payloadLength % blockSize)
        if paddingLength < 4 {
            paddingLength += blockSize
        }

        /// packet_length
        ///   The length of the packet in bytes, not including 'mac' or the 'packet_length' field itself.
        let packetLength = 1 + messageLength + paddingLength
        self.setInteger(UInt32(packetLength), at: index)
        /// padding_length
        self.setInteger(UInt8(paddingLength), at: index + 4)
        /// random padding
        self.writeSSHPaddingBytes(count: paddingLength)
    }
}
