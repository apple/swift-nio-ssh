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
import NIOCore

/// This structure represents the SSH understanding of POSIX terminal modes.
///
/// SSH has the ability to express "terminal modes" when requesting a PTY. The client is
/// expected to express all modes it knows about, with the server ignoring anything that it
/// does not know anything about.
public struct SSHTerminalModes {
    public var modeMapping: [Opcode: OpcodeValue]

    public init(_ modeMapping: [Opcode: OpcodeValue]) {
        self.modeMapping = modeMapping
    }
}

extension SSHTerminalModes: Hashable {}

extension SSHTerminalModes: NIOSSHSendable {}

// MARK: Opcode

extension SSHTerminalModes {
    /// A terminal mode opcode.
    public struct Opcode {
        /// The raw value of the terminal mode opcode.
        public var rawValue: UInt8 {
            get {
                self._rawValue
            }
            set {
                precondition(newValue != 0) // Reserved for TTY_OP_END.
                self._rawValue = newValue
            }
        }

        private var _rawValue: UInt8

        public init(rawValue: UInt8) {
            precondition(rawValue != 0) // Reserved for TTY_OP_END.
            self._rawValue = rawValue
        }

        /// Interrupt character; 255 if none.  Similarly for the other characters.  Not all of these characters are supported on all systems.
        public static let VINTR = Opcode(rawValue: 1)

        /// The quit character (sends SIGQUIT signal on POSIX systems).
        public static let VQUIT = Opcode(rawValue: 2)

        /// Erase the character to left of the cursor.
        public static let VERASE = Opcode(rawValue: 3)

        /// Kill the current input line.
        public static let VKILL = Opcode(rawValue: 4)

        /// End-of-file character (sends EOF from the terminal).
        public static let VEOF = Opcode(rawValue: 5)

        /// End-of-line character in addition to carriage return and/or linefeed.
        public static let VEOL = Opcode(rawValue: 6)

        /// Additional end-of-line character.
        public static let VEOL2 = Opcode(rawValue: 7)

        /// Continues paused output (normally control-Q).
        public static let VSTART = Opcode(rawValue: 8)

        /// Pauses output (normally control-S).
        public static let VSTOP = Opcode(rawValue: 9)

        /// Suspends the current program.
        public static let VSUSP = Opcode(rawValue: 10)

        /// Another suspend character.
        public static let VDSUSP = Opcode(rawValue: 11)

        /// Reprints the current input line.
        public static let VREPRINT = Opcode(rawValue: 12)

        /// Erases a word left of cursor.
        public static let VWERASE = Opcode(rawValue: 13)

        /// Enter the next character typed literally, even if it is a special character
        public static let VLNEXT = Opcode(rawValue: 14)

        /// Character to flush output.
        public static let VFLUSH = Opcode(rawValue: 15)

        /// Switch to a different shell layer.
        public static let VSWTCH = Opcode(rawValue: 16)

        /// Prints system status line (load, command, pid, etc).
        public static let VSTATUS = Opcode(rawValue: 17)

        /// Toggles the flushing of terminal output.
        public static let VDISCARD = Opcode(rawValue: 18)

        /// The ignore parity flag. The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE.
        public static let IGNPAR = Opcode(rawValue: 30)

        /// Mark parity and framing errors.
        public static let PARMRK = Opcode(rawValue: 31)

        /// Enable checking of parity errors.
        public static let INPCK = Opcode(rawValue: 32)

        /// Strip 8th bit off characters.
        public static let ISTRIP = Opcode(rawValue: 33)

        /// Map NL into CR on input.
        public static let INLCR = Opcode(rawValue: 34)

        /// Ignore CR on input.
        public static let IGNCR = Opcode(rawValue: 35)

        /// Map CR to NL on input.
        public static let ICRNL = Opcode(rawValue: 36)

        /// Translate uppercase characters to lowercase.
        public static let IUCLC = Opcode(rawValue: 37)

        /// Enable output flow control.
        public static let IXON = Opcode(rawValue: 38)

        /// Any char will restart after stop.
        public static let IXANY = Opcode(rawValue: 39)

        /// Enable input flow control.
        public static let IXOFF = Opcode(rawValue: 40)

        /// Ring bell on input queue full.
        public static let IMAXBEL = Opcode(rawValue: 41)

        /// Enable signals INTR, QUIT, [D]SUSP.
        public static let ISIG = Opcode(rawValue: 50)

        /// Canonicalize input lines.
        public static let ICANON = Opcode(rawValue: 51)

        /// Enable input and output of uppercase characters by preceding their lowercase equivalents with "\".
        public static let XCASE = Opcode(rawValue: 52)

        /// Enable echoing.
        public static let ECHO = Opcode(rawValue: 53)

        /// Visually erase chars.
        public static let ECHOE = Opcode(rawValue: 54)

        /// Kill character discards current line.
        public static let ECHOK = Opcode(rawValue: 55)

        /// Echo NL even if ECHO is off.
        public static let ECHONL = Opcode(rawValue: 56)

        /// Don't flush after interrupt.
        public static let NOFLSH = Opcode(rawValue: 57)

        /// Stop background jobs from output.
        public static let TOSTOP = Opcode(rawValue: 58)

        /// Enable extensions.
        public static let IEXTEN = Opcode(rawValue: 59)

        /// Echo control characters as ^(Char).
        public static let ECHOCTL = Opcode(rawValue: 60)

        /// Visual erase for line kill.
        public static let ECHOKE = Opcode(rawValue: 61)

        /// Retype pending input.
        public static let PENDIN = Opcode(rawValue: 62)

        /// Enable output processing.
        public static let OPOST = Opcode(rawValue: 70)

        /// Convert lowercase to uppercase.
        public static let OLCUC = Opcode(rawValue: 71)

        /// Map NL to CR-NL.
        public static let ONLCR = Opcode(rawValue: 72)

        /// Translate carriage return to newline (output).
        public static let OCRNL = Opcode(rawValue: 73)

        /// Translate newline to carriage return-newline (output).
        public static let ONOCR = Opcode(rawValue: 74)

        /// Newline performs a carriage return (output).
        public static let ONLRET = Opcode(rawValue: 75)

        /// 7 bit mode.
        public static let CS7 = Opcode(rawValue: 90)

        /// 8 bit mode.
        public static let CS8 = Opcode(rawValue: 91)

        /// Parity enable.
        public static let PARENB = Opcode(rawValue: 92)

        /// Odd parity, else even.
        public static let PARODD = Opcode(rawValue: 93)

        /// Specifies the input baud rate in bits per second.
        public static let TTY_OP_ISPEED = Opcode(rawValue: 128)

        /// Specifies the output baud rate in bits per second.
        public static let TTY_OP_OSPEED = Opcode(rawValue: 129)
    }
}

extension SSHTerminalModes.Opcode: Hashable {}

extension SSHTerminalModes.Opcode: NIOSSHSendable {}

extension SSHTerminalModes.Opcode: Comparable {
    public static func < (lhs: SSHTerminalModes.Opcode, rhs: SSHTerminalModes.Opcode) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

extension SSHTerminalModes.Opcode: RawRepresentable {}

extension SSHTerminalModes.Opcode: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: UInt8) {
        self = .init(rawValue: value)
    }
}

extension SSHTerminalModes.Opcode: CustomStringConvertible {
    public var description: String {
        switch self {
        case .VINTR:
            return "SSHTerminalModes.Opcode.VINTR"
        case .VQUIT:
            return "SSHTerminalModes.Opcode.VQUIT"
        case .VERASE:
            return "SSHTerminalModes.Opcode.VERASE"
        case .VKILL:
            return "SSHTerminalModes.Opcode.VKILL"
        case .VEOF:
            return "SSHTerminalModes.Opcode.VEOF"
        case .VEOL:
            return "SSHTerminalModes.Opcode.VEOL"
        case .VEOL2:
            return "SSHTerminalModes.Opcode.VEOL2"
        case .VSTART:
            return "SSHTerminalModes.Opcode.VSTART"
        case .VSTOP:
            return "SSHTerminalModes.Opcode.VSTOP"
        case .VSUSP:
            return "SSHTerminalModes.Opcode.VSUSP"
        case .VDSUSP:
            return "SSHTerminalModes.Opcode.VDSUSP"
        case .VREPRINT:
            return "SSHTerminalModes.Opcode.VREPRINT"
        case .VWERASE:
            return "SSHTerminalModes.Opcode.VWERASE"
        case .VLNEXT:
            return "SSHTerminalModes.Opcode.VLNEXT"
        case .VFLUSH:
            return "SSHTerminalModes.Opcode.VFLUSH"
        case .VSWTCH:
            return "SSHTerminalModes.Opcode.VSWTCH"
        case .VSTATUS:
            return "SSHTerminalModes.Opcode.VSTATUS"
        case .VDISCARD:
            return "SSHTerminalModes.Opcode.VDISCARD"
        case .IGNPAR:
            return "SSHTerminalModes.Opcode.IGNPAR"
        case .PARMRK:
            return "SSHTerminalModes.Opcode.PARMRK"
        case .INPCK:
            return "SSHTerminalModes.Opcode.INPCK"
        case .ISTRIP:
            return "SSHTerminalModes.Opcode.ISTRIP"
        case .INLCR:
            return "SSHTerminalModes.Opcode.INLCR"
        case .IGNCR:
            return "SSHTerminalModes.Opcode.IGNCR"
        case .ICRNL:
            return "SSHTerminalModes.Opcode.ICRNL"
        case .IUCLC:
            return "SSHTerminalModes.Opcode.IUCLC"
        case .IXON:
            return "SSHTerminalModes.Opcode.IXON"
        case .IXANY:
            return "SSHTerminalModes.Opcode.IXANY"
        case .IXOFF:
            return "SSHTerminalModes.Opcode.IXOFF"
        case .IMAXBEL:
            return "SSHTerminalModes.Opcode.IMAXBEL"
        case .ISIG:
            return "SSHTerminalModes.Opcode.ISIG"
        case .ICANON:
            return "SSHTerminalModes.Opcode.ICANON"
        case .XCASE:
            return "SSHTerminalModes.Opcode.XCASE"
        case .ECHO:
            return "SSHTerminalModes.Opcode.ECHO"
        case .ECHOE:
            return "SSHTerminalModes.Opcode.ECHOE"
        case .ECHOK:
            return "SSHTerminalModes.Opcode.ECHOK"
        case .ECHONL:
            return "SSHTerminalModes.Opcode.ECHONL"
        case .NOFLSH:
            return "SSHTerminalModes.Opcode.NOFLSH"
        case .TOSTOP:
            return "SSHTerminalModes.Opcode.TOSTOP"
        case .IEXTEN:
            return "SSHTerminalModes.Opcode.IEXTEN"
        case .ECHOCTL:
            return "SSHTerminalModes.Opcode.ECHOCTL"
        case .ECHOKE:
            return "SSHTerminalModes.Opcode.ECHOKE"
        case .PENDIN:
            return "SSHTerminalModes.Opcode.PENDIN"
        case .OPOST:
            return "SSHTerminalModes.Opcode.OPOST"
        case .OLCUC:
            return "SSHTerminalModes.Opcode.OLCUC"
        case .ONLCR:
            return "SSHTerminalModes.Opcode.ONLCR"
        case .OCRNL:
            return "SSHTerminalModes.Opcode.OCRNL"
        case .ONOCR:
            return "SSHTerminalModes.Opcode.ONOCR"
        case .ONLRET:
            return "SSHTerminalModes.Opcode.ONLRET"
        case .CS7:
            return "SSHTerminalModes.Opcode.CS7"
        case .CS8:
            return "SSHTerminalModes.Opcode.CS8"
        case .PARENB:
            return "SSHTerminalModes.Opcode.PARENB"
        case .PARODD:
            return "SSHTerminalModes.Opcode.PARODD"
        case .TTY_OP_ISPEED:
            return "SSHTerminalModes.Opcode.TTY_OP_ISPEED"
        case .TTY_OP_OSPEED:
            return "SSHTerminalModes.Opcode.TTY_OP_OSPEED"
        default:
            return "SSHTerminalModes.Opcode(rawValue: \(self.rawValue))"
        }
    }
}

// MARK: OpcodeValue

extension SSHTerminalModes {
    /// The value of an SSH terminal mode opcode.
    public struct OpcodeValue {
        /// The raw value of this opcode.
        public var rawValue: UInt32

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
    }
}

extension SSHTerminalModes.OpcodeValue: Hashable {}

extension SSHTerminalModes.OpcodeValue: NIOSSHSendable {}

extension SSHTerminalModes.OpcodeValue: Comparable {
    public static func < (lhs: SSHTerminalModes.OpcodeValue, rhs: SSHTerminalModes.OpcodeValue) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

extension SSHTerminalModes.OpcodeValue: RawRepresentable {}

extension SSHTerminalModes.OpcodeValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: UInt32) {
        self.rawValue = value
    }
}

extension ByteBuffer {
    mutating func readSSHTerminalModes() throws -> SSHTerminalModes {
        var mapping: [SSHTerminalModes.Opcode: SSHTerminalModes.OpcodeValue] = [:]
        mapping.reserveCapacity(self.readableBytes / 5)

        return try self.rewindReaderOnError { `self` in
            // Opcodes 1 to 159 have a single uint32 argument.  Opcodes 160 to 255 are not yet
            // defined, and cause parsing to stop (they should only be used after any other data).
            // The stream is terminated by opcode TTY_OP_END (0x00).
            while let opcode = self.readInteger(as: UInt8.self), (1 ..< 159).contains(opcode) {
                guard let value = self.readInteger(as: UInt32.self) else {
                    throw NIOSSHError.protocolViolation(protocolName: "ssh-connection", violation: "invalid encoded terminal modes")
                }

                mapping[SSHTerminalModes.Opcode(rawValue: opcode)] = SSHTerminalModes.OpcodeValue(rawValue: value)
            }

            return SSHTerminalModes(mapping)
        }
    }

    @discardableResult
    mutating func writeSSHTerminalModes(_ modes: SSHTerminalModes) -> Int {
        var written = 0
        for (mode, value) in modes.modeMapping {
            written += self.writeInteger(mode.rawValue)
            written += self.writeInteger(value.rawValue)
        }

        written += self.writeInteger(UInt8(0))
        return written
    }
}
