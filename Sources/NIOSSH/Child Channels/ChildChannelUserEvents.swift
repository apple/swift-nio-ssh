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

import NIO


/// A namespace for SSH channel request events.
public enum SSHChannelRequestEvent {
    public struct PseudoTerminalRequest: Hashable {
        /// Whether a reply to this PTY request is desired.
        public var wantReply: Bool

        /// The value of the TERM environment variable, e.g. "vt100"
        public var term: String

        /// The desired width of the terminal in characters. This overrides
        /// the pixel width when this value is non-zero.
        public var terminalCharacterWidth: Int {
            return Int(self._terminalCharacterWidth)
        }

        /// The desired height of the terminal in rows. This overrides the pixel height
        /// when this value is non-zero.
        public var terminalRowHeight: Int {
            return Int(self._terminalRowHeight)
        }

        /// The desired width of the terminal in pixels. This is overriden by the character
        /// width if that value is non-zero.
        public var terminalPixelWidth: Int {
            return Int(self._terminalPixelWidth)
        }

        /// The desired height of the terminal in pixels. This is overridden by the row
        /// height if that value is non-zero.
        public var terminalPixelHeight: Int {
            return Int(self._terminalPixelHeight)
        }

        /// The posix terminal modes.
        public var terminalModes: SSHTerminalModes

        private var _terminalCharacterWidth: UInt32

        private var _terminalRowHeight: UInt32

        private var _terminalPixelWidth: UInt32

        private var _terminalPixelHeight: UInt32

        public init(wantReply: Bool,
                    term: String,
                    terminalCharacterWidth: Int,
                    terminalRowHeight: Int,
                    terminalPixelWidth: Int,
                    terminalPixelHeight: Int,
                    terminalModes: SSHTerminalModes) {
            self = .init(wantReply: wantReply,
                         term: term,
                         terminalCharacterWidth: UInt32(terminalCharacterWidth),
                         terminalRowHeight: UInt32(terminalRowHeight),
                         terminalPixelWidth: UInt32(terminalPixelWidth),
                         terminalPixelHeight: UInt32(terminalPixelHeight),
                         terminalModes: terminalModes)
        }

        internal init(wantReply: Bool,
                      term: String,
                      terminalCharacterWidth: UInt32,
                      terminalRowHeight: UInt32,
                      terminalPixelWidth: UInt32,
                      terminalPixelHeight: UInt32,
                      terminalModes: SSHTerminalModes) {
            self.wantReply = wantReply
            self.term = term
            self._terminalCharacterWidth = terminalCharacterWidth
            self._terminalRowHeight = terminalRowHeight
            self._terminalPixelWidth = terminalPixelWidth
            self._terminalPixelHeight = terminalPixelHeight
            self.terminalModes = terminalModes
        }
    }

    /// An EnvironmentRequest communicates a single environment variable the peer wants set.
    public struct EnvironmentRequest: Hashable {
        /// The name of the environment variable.
        public var name: String

        /// The value of the environment variable
        public var value: String

        /// Whether this request should be replied to.
        public var wantReply: Bool

        public init(wantReply: Bool, name: String, value: String) {
            self.wantReply = wantReply
            self.name = name
            self.value = value
        }
    }

    /// A request for this session to invoke a shell.
    public struct ShellRequest: Hashable {
        /// Whether this request should be replied to.
        public var wantReply: Bool

        public init(wantReply: Bool) {
            self.wantReply = wantReply
        }
    }

    /// A request for this session to exec a command.
    public struct ExecRequest: Hashable {
        /// The command to exec.
        public var command: String

        /// Whether this request should be replied to.
        public var wantReply: Bool

        public init(command: String, wantReply: Bool) {
            self.command = command
            self.wantReply = wantReply
        }
    }

    /// The command has exited with the given exit status.
    public struct ExitStatus: Hashable {
        /// Whether this request should be replied to.
        public var wantReply: Bool {
            return false
        }

        /// The exit status code.
        public var exitStatus: Int {
            get {
                return Int(self._exitStatus)
            }
            set {
                self._exitStatus = UInt32(newValue)
            }
        }

        private var _exitStatus: UInt32

        public init(exitStatus: Int) {
            self._exitStatus = UInt32(exitStatus)
        }

        fileprivate init(exitStatus: UInt32) {
            self._exitStatus = exitStatus
        }
    }
}

extension SSHChannelRequestEvent {
    /// Constructs a channel request event and wraps it up in an Any.
    ///
    /// This is usually used just prior to firing this into the pipeline.
    internal static func fromMessage(_ message: SSHMessage.ChannelRequestMessage) -> Optional<Any> {
        switch message.type {
        case .env(let name, let value):
            return EnvironmentRequest(wantReply: message.wantReply, name: name, value: value) as Any
        case .exec(let command):
            return ExecRequest(command: command, wantReply: message.wantReply) as Any
        case .exit(let code):
            return ExitStatus(exitStatus: code) as Any
        case .unknown:
            return nil
        }
    }
}

/// A channel success message was received in reply to a channel request.
public struct ChannelSuccessEvent: Hashable {
    public init() { }
}

/// A channel failure message was received in reply to a channel request.
public struct ChannelFailureEvent: Hashable {
    public init() { }
}

// MARK: Convert to messages
extension SSHMessage {
    init(_ event: SSHChannelRequestEvent.ExecRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel, type: .exec(event.command), wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init( _ event: SSHChannelRequestEvent.EnvironmentRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel, type: .env(event.name, event.value), wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.ExitStatus, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel, type: .exit(UInt32(event.exitStatus)), wantReply: event.wantReply)
        self = .channelRequest(message)
    }
}
