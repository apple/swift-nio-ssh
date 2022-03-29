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

/// A namespace for SSH channel request events.
public enum SSHChannelRequestEvent {
    public struct PseudoTerminalRequest: Hashable, NIOSSHSendable {
        /// Whether a reply to this PTY request is desired.
        public var wantReply: Bool

        /// The value of the TERM environment variable, e.g. "vt100"
        public var term: String

        /// The desired width of the terminal in characters. This overrides
        /// the pixel width when this value is non-zero.
        public var terminalCharacterWidth: Int {
            Int(self._terminalCharacterWidth)
        }

        /// The desired height of the terminal in rows. This overrides the pixel height
        /// when this value is non-zero.
        public var terminalRowHeight: Int {
            Int(self._terminalRowHeight)
        }

        /// The desired width of the terminal in pixels. This is overriden by the character
        /// width if that value is non-zero.
        public var terminalPixelWidth: Int {
            Int(self._terminalPixelWidth)
        }

        /// The desired height of the terminal in pixels. This is overridden by the row
        /// height if that value is non-zero.
        public var terminalPixelHeight: Int {
            Int(self._terminalPixelHeight)
        }

        /// The posix terminal modes.
        public var terminalModes: SSHTerminalModes

        fileprivate var _terminalCharacterWidth: UInt32

        fileprivate var _terminalRowHeight: UInt32

        fileprivate var _terminalPixelWidth: UInt32

        fileprivate var _terminalPixelHeight: UInt32

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
    public struct EnvironmentRequest: Hashable, NIOSSHSendable {
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
    public struct ShellRequest: Hashable, NIOSSHSendable {
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
    public struct ExitStatus: Hashable, NIOSSHSendable {
        /// Whether this request should be replied to.
        public var wantReply: Bool {
            false
        }

        /// The exit status code.
        public var exitStatus: Int {
            get {
                Int(self._exitStatus)
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

    /// A command has terminated in response to a signal.
    public struct ExitSignal: Hashable, NIOSSHSendable {
        /// Whether this request should be replied to.
        public var wantReply: Bool {
            false
        }

        /// The name of the signal, without the "SIG" prefix, e.g. "USR1".
        public var signalName: String

        /// The error message associated with the signal.
        public var errorMessage: String

        /// The language tag.
        public var language: String

        /// Whether the command dumped a core file.
        public var dumpedCore: Bool

        public init(signalName: String, errorMessage: String, language: String, dumpedCore: Bool) {
            self.signalName = signalName
            self.errorMessage = errorMessage
            self.language = language
            self.dumpedCore = dumpedCore
        }
    }

    /// A request for this session to invoke a specific subsystem.
    public struct SubsystemRequest: Hashable, NIOSSHSendable {
        /// Whether this request wants a reply.
        public var wantReply: Bool

        /// The name of the subsystem to invoke.
        public var subsystem: String

        public init(subsystem: String, wantReply: Bool) {
            self.subsystem = subsystem
            self.wantReply = wantReply
        }
    }

    public struct WindowChangeRequest: Hashable, NIOSSHSendable {
        /// Whether a reply to this window change request is desired.
        public var wantReply: Bool {
            false
        }

        /// The desired width of the terminal in characters. This overrides
        /// the pixel width when this value is non-zero.
        public var terminalCharacterWidth: Int {
            Int(self._terminalCharacterWidth)
        }

        /// The desired height of the terminal in rows. This overrides the pixel height
        /// when this value is non-zero.
        public var terminalRowHeight: Int {
            Int(self._terminalRowHeight)
        }

        /// The desired width of the terminal in pixels. This is overriden by the character
        /// width if that value is non-zero.
        public var terminalPixelWidth: Int {
            Int(self._terminalPixelWidth)
        }

        /// The desired height of the terminal in pixels. This is overridden by the row
        /// height if that value is non-zero.
        public var terminalPixelHeight: Int {
            Int(self._terminalPixelHeight)
        }

        fileprivate var _terminalCharacterWidth: UInt32

        fileprivate var _terminalRowHeight: UInt32

        fileprivate var _terminalPixelWidth: UInt32

        fileprivate var _terminalPixelHeight: UInt32

        public init(terminalCharacterWidth: Int,
                    terminalRowHeight: Int,
                    terminalPixelWidth: Int,
                    terminalPixelHeight: Int) {
            self = .init(terminalCharacterWidth: UInt32(terminalCharacterWidth),
                         terminalRowHeight: UInt32(terminalRowHeight),
                         terminalPixelWidth: UInt32(terminalPixelWidth),
                         terminalPixelHeight: UInt32(terminalPixelHeight))
        }

        internal init(terminalCharacterWidth: UInt32,
                      terminalRowHeight: UInt32,
                      terminalPixelWidth: UInt32,
                      terminalPixelHeight: UInt32) {
            self._terminalCharacterWidth = terminalCharacterWidth
            self._terminalRowHeight = terminalRowHeight
            self._terminalPixelWidth = terminalPixelWidth
            self._terminalPixelHeight = terminalPixelHeight
        }
    }

    /// A request to allow flow control to be managed at the client.
    ///
    /// This is sent by the server. If "client can do" is true, the client may do flow control with
    /// ctrl+s and ctrl+q.
    public struct LocalFlowControlRequest: Hashable, NIOSSHSendable {
        /// Whether a reply to this request is desired.
        public var wantReply: Bool {
            false
        }

        /// Whether the client is allowed to use local flow control.
        public var clientCanDo: Bool

        public init(clientCanDo: Bool) {
            self.clientCanDo = clientCanDo
        }
    }

    /// Delivers a signal to the remote process.
    public struct SignalRequest: Hashable, NIOSSHSendable {
        /// Whether a reply to this request is desired.
        public var wantReply: Bool {
            false
        }

        /// The name of the signal (without the "SIG" prefix), e.g. "USR1".
        public var signal: String

        public init(signal: String) {
            self.signal = signal
        }
    }
}

extension SSHChannelRequestEvent {
    /// Constructs a channel request event and wraps it up in an Any.
    ///
    /// This is usually used just prior to firing this into the pipeline.
    internal static func fromMessage(_ message: SSHMessage.ChannelRequestMessage) -> Any? {
        switch message.type {
        case .env(let name, let value):
            return EnvironmentRequest(wantReply: message.wantReply, name: name, value: value) as Any
        case .exec(let command):
            return ExecRequest(command: command, wantReply: message.wantReply) as Any
        case .exitStatus(let code):
            return ExitStatus(exitStatus: code) as Any
        case .exitSignal(let name, let dumpedCore, let errorMessage, let language):
            return ExitSignal(signalName: name, errorMessage: errorMessage, language: language, dumpedCore: dumpedCore) as Any
        case .ptyReq(let ptyReq):
            return PseudoTerminalRequest(wantReply: message.wantReply,
                                         term: ptyReq.termVariable,
                                         terminalCharacterWidth: ptyReq.characterWidth,
                                         terminalRowHeight: ptyReq.rowHeight,
                                         terminalPixelWidth: ptyReq.pixelWidth,
                                         terminalPixelHeight: ptyReq.pixelHeight,
                                         terminalModes: ptyReq.terminalModes)
        case .shell:
            return ShellRequest(wantReply: message.wantReply) as Any
        case .subsystem(let subsystem):
            return SubsystemRequest(subsystem: subsystem, wantReply: message.wantReply) as Any
        case .windowChange(let windowChange):
            return WindowChangeRequest(terminalCharacterWidth: windowChange.characterWidth,
                                       terminalRowHeight: windowChange.rowHeight,
                                       terminalPixelWidth: windowChange.pixelWidth,
                                       terminalPixelHeight: windowChange.pixelHeight)
        case .xonXoff(let clientCanDo):
            return LocalFlowControlRequest(clientCanDo: clientCanDo) as Any
        case .signal(let signalName):
            return SignalRequest(signal: signalName)
        case .unknown:
            return nil
        }
    }
}

/// A channel success message was received in reply to a channel request.
public struct ChannelSuccessEvent: Hashable, NIOSSHSendable {
    public init() {}
}

/// A channel failure message was received in reply to a channel request.
public struct ChannelFailureEvent: Hashable, NIOSSHSendable {
    public init() {}
}

// MARK: Convert to messages

extension SSHMessage {
    init(_ event: SSHChannelRequestEvent.ShellRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel, type: .shell, wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.PseudoTerminalRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel,
                                                       type: .ptyReq(.init(termVariable: event.term,
                                                                           characterWidth: event._terminalCharacterWidth,
                                                                           rowHeight: event._terminalRowHeight,
                                                                           pixelWidth: event._terminalPixelWidth,
                                                                           pixelHeight: event._terminalPixelHeight,
                                                                           terminalModes: event.terminalModes)),
                                                       wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.ExecRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel, type: .exec(event.command), wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.EnvironmentRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel, type: .env(event.name, event.value), wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.ExitStatus, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel, type: .exitStatus(UInt32(event.exitStatus)), wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.ExitSignal, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel,
                                                       type: .exitSignal(event.signalName, event.dumpedCore, event.errorMessage, event.language),
                                                       wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.SubsystemRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel,
                                                       type: .subsystem(event.subsystem),
                                                       wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.WindowChangeRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel,
                                                       type: .windowChange(.init(characterWidth: event._terminalCharacterWidth,
                                                                                 rowHeight: event._terminalRowHeight,
                                                                                 pixelWidth: event._terminalPixelWidth,
                                                                                 pixelHeight: event._terminalPixelHeight)),
                                                       wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.LocalFlowControlRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel,
                                                       type: .xonXoff(event.clientCanDo),
                                                       wantReply: event.wantReply)
        self = .channelRequest(message)
    }

    init(_ event: SSHChannelRequestEvent.SignalRequest, recipientChannel: UInt32) {
        let message = SSHMessage.ChannelRequestMessage(recipientChannel: recipientChannel,
                                                       type: .signal(event.signal),
                                                       wantReply: event.wantReply)
        self = .channelRequest(message)
    }
}
