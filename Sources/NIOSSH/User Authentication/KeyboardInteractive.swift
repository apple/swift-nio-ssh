//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A single prompt within a keyboard-interactive authentication challenge (RFC 4256).
public struct NIOSSHKeyboardInteractivePrompt: Sendable, Hashable {
    /// The text to display to the user when requesting a response.
    public var prompt: String

    /// Whether the client should echo the user's response as it is typed.
    ///
    /// When this is `false` the response is sensitive (for example a password or one-time code)
    /// and must not be displayed or logged.
    public var echo: Bool

    public init(prompt: String, echo: Bool) {
        self.prompt = prompt
        self.echo = echo
    }
}

/// A keyboard-interactive authentication challenge (RFC 4256), issued by the server.
///
/// A single keyboard-interactive authentication attempt may involve any number of challenges. For
/// each challenge the client must provide exactly one response per ``prompts`` entry, in order.
public struct NIOSSHKeyboardInteractiveChallenge: Sendable, Hashable {
    /// The name of the challenge, which may be displayed to the user as a title. May be empty.
    public var name: String

    /// Instructions to display to the user. May be empty.
    public var instruction: String

    /// A language tag, per RFC 4256. Usually empty.
    public var languageTag: String

    /// The prompts the user must respond to, in order. May be empty, in which case the client must
    /// respond with an empty list of responses.
    public var prompts: [NIOSSHKeyboardInteractivePrompt]

    public init(
        name: String,
        instruction: String,
        languageTag: String,
        prompts: [NIOSSHKeyboardInteractivePrompt]
    ) {
        self.name = name
        self.instruction = instruction
        self.languageTag = languageTag
        self.prompts = prompts
    }
}

extension NIOSSHKeyboardInteractiveChallenge {
    internal init(_ message: SSHMessage.UserAuthInfoRequestMessage) {
        self.name = message.name
        self.instruction = message.instruction
        self.languageTag = message.languageTag
        self.prompts = message.prompts.map { .init(prompt: $0.prompt, echo: $0.echo) }
    }
}
