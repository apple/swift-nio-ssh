# SwiftNIO SSH

This project contains SSH support using [SwiftNIO](https://github.com/apple/swift-nio).

## What is SwiftNIO SSH?

SwiftNIO SSH is a programmatic implementation of SSH: that is, it is a collection of APIs that allow programmers to implement SSH-speaking endpoints. Critically, this means it is more like libssh2 than openssh. SwiftNIO SSH does not ship production-ready SSH clients and servers, but instead provides the building blocks for building this kind of client and server.

There are a number of reasons to provide a programmatic SSH implementation. One is that SSH has a unique relationship to user interactivity. Technical users are highly accustomed to interacting with SSH interactively, either to run commands on remote machines or to run interactive shells. Having the ability to programmatically respond to these requests enables interesting alternative modes of interaction. As prior examples, we can point to Twisted's Manhole, which uses [a programmatic SSH implementation called `conch`](https://twistedmatrix.com/trac/wiki/TwistedConch) to provide an interactive Python interpreter within a running Python server, or [ssh-chat](https://github.com/shazow/ssh-chat), a SSH server that provides a chat room instead of regular SSH shell functionality. Innovative uses can also be imagined for TCP forwarding.

Another good reason to provide programmatic SSH is that it is not uncommon for services to need to interact with other services in a way that involves running commands. While `Process` solves this for the local use-case, sometimes the commands that need to be invoked are remote. While `Process` could launch an `ssh` client as a sub-process in order to run this invocation, it can be substantially more straightforward to simply invoke SSH directly. This is [`libssh2`](https://www.libssh2.org)'s target use-case. SwiftNIO SSH provides the equivalent of the networking and cryptographic layer of libssh2, allowing motivated users to drive SSH sessions directly from within Swift services.

SwiftNIO SSH requires Swift 5.4 and newer. 0.3.x supports Swift 5.2 and 5.3, 0.2.x supports Swift 5.1.

## What does SwiftNIO SSH support?

SwiftNIO SSH supports SSHv2 with the following feature set:

- All session channel features, including shell and exec channel requests
- Direct and reverse TCP port forwarding
- Modern cryptographic primitives only: Ed25519 and ECDSA over the major NIST curves (P256, P384, P521) for asymmetric cryptography, AES-GCM for symmetric cryptography, x25519 for key exchange
- Password and public key user authentication
- Supports all platforms supported by SwiftNIO and Swift Crypto

## How do I use SwiftNIO SSH?

SwiftNIO SSH provides a SwiftNIO `ChannelHandler`, `NIOSSHHandler`. This handler implements the bulk of the SSH protocol directly. Users are not expected to generate SSH messages directly: instead, they interact with the `NIOSSHHandler` through child channels and delegates.

SSH is a multiplexed protocol: each SSH connection is subdivided into multiple bidirectional communication channels called, appropriately enough, channels. SwiftNIO SSH reflects this construction by using a "child channel" abstraction. When a peer creates a new SSH channel, SwiftNIO SSH will create a new NIO `Channel` that is used to represent all traffic on that SSH channel. Within this child `Channel` all events are strictly ordered with respect to one another: however, events in different `Channel`s may be interleaved freely by the implementation.

An active SSH connection therefore looks like this:

```
┌ ─ NIO Channel ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

│     ┌────────────────────────────────┐    │
      │                                │
│     │                                │    │
      │                                │
│     │                                │    │
      │         NIOSSHHandler          │───────────────────────┐
│     │                                │    │                  │
      │                                │                       │
│     │                                │    │                  │
      │                                │                       │
│     └────────────────────────────────┘    │                  │
                                                               │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘                  │
                                                               │
                                                               │
                                                               │
                                                               │
                                                               ▼
                     ┌── SSH Child Channel ─────────────────────────────────────────────────────────────┐
                     │                                                                                  │
                     │   ┌────────────────────────────────┐      ┌────────────────────────────────┐     ├───┐
                     │   │                                │      │                                │     │   │
                     │   │                                │      │                                │     │   ├───┐
                     │   │                                │      │                                │     │   │   │
                     │   │                                │      │                                │     │   │   │
                     │   │          User Handler          │      │          User Handler          │     │   │   │
                     │   │                                │      │                                │     │   │   │
                     │   │                                │      │                                │     │   │   │
                     │   │                                │      │                                │     │   │   │
                     │   │                                │      │                                │     │   │   │
                     │   └────────────────────────────────┘      └────────────────────────────────┘     │   │   │
                     │                                                                                  │   │   │
                     └───┬──────────────────────────────────────────────────────────────────────────────┘   │   │
                         │                                                                                  │   │
                         └───┬──────────────────────────────────────────────────────────────────────────────┘   │
                             │                                                                                  │
                             └──────────────────────────────────────────────────────────────────────────────────┘
```

An SSH channel is invoked with a channel type. NIOSSH supports three: `session`, `directTCPIP`, and `forwardedTCPIP`. The most common channel type is `session`: `session` is used to represent the invocation of a program, whether a specific named program or a shell. The other two channel types are related to TCP port forwarding, and will be discussed later.

An SSH channel operates on a single data type: `SSHChannelData`. This structure encapsulates the fact that SSH supports both regular and "extended" channel data. The regular channel data (`SSHChannelData.DataType.channel`) is used for the vast majority of core data. In `session` channels the `.channel` data type is used for standard input and standard output: the `.stdErr` data type is used for standard error (naturally). In TCP forwarding channels, the `.channel` data type is the only kind used, and represents the forwarded data.

### Channel Events

A `session` channel represents an invocation of a command. Exactly how the channel operates is communicated in a number of inbound user events. The following events are important:

- `SSHChannelRequestEvent.PseudoTerminalRequest`: Requests the allocation of a pseudo-terminal.
- `SSHChannelRequestEvent.EnvironmentRequest`: Requests a single environment variable for the command invocation. Always sent before the command itself.
- `SSHChannelRequestEvent.ShellRequest`: Requests that the command to be invoked is the authenticated user's shell.
- `SSHChannelRequestEvent.ExecRequest`: Requests the invocation of a specific command.
- `SSHChannelRequestEvent.ExitStatus`: Used to signal that the remote command has exited, and communicates the exit code.
- `SSHChannelRequestEvent.ExitSignal`: Used to indicate that the remote command was terminated in response to a signal, and what that signal was.
- `SSHChannelRequestEvent.SignalRequest`:  Used to send a signal to the remote command.
- `SSHChannelRequestEvent.LocalFlowControlRequest`: Used to indicate whether the client is capable of performing Ctrl-Q/Ctrl-S flow control itself.
- `SSHChannelRequestEvent.WindowChangeRequest`: Used to communicate a change in the size of the terminal window on the client to the allocated peudo-terminal.
- `SSHChannelRequestEvent.SubsystemRequest`: Used to request invocation of a specific subsystem. The meaning of this is specific to individual use-cases.

These events are unused in port forwarding messages. SSH implementations that support `.session` type channels need to be prepared to handle most or all of these in various ways.

Each of these events also has a `wantReply` field. This indicates whether the request need a reply to indicate success or failure. If it does, the following two events are used:

- `ChannelSuccessEvent`, to communicate success.
- `ChannelFailureEvent`, to communicate failure.

### Half Closure

The SSH network protocol pervasively uses half-closure in the child channels. NIO `Channel`s typically have half-closure support disabled by default, and SwiftNIO SSH respects this default in its child channels as well. However, if you leave this setting at its default value the SSH child channels will behave extremely unexpectedly. For this reason, it is strongly recommended that all child channels have half closure support enabled:

```swift
channel.setOption(ChannelOptions.allowRemoteHalfClosure, true)
```

This then uses standard NIO half-closure support. The remote peer sending EOF will be communicated with an inbound user event, `ChannelEvent.inputClosed`. To send EOF yourself, call `close(mode: .output)`.

### User Authentication

User authentication is a vital part of SSH. To manage it, SwiftNIO SSH uses a pair of delegate protocols: `NIOSSHClientUserAuthenticationDelegate` and `NIOSSHServerUserAuthenticationDelegate`. Clients and servers should provide implementations of these delegate protocols to manage user authentication.

The client protocol is straightforward: SwiftNIO SSH will invoke the method `nextAuthenticationType(availableMethods:nextChallengePromise:)` on the delegate. The `availableMethods` will be an instance of `NIOSSHAvailableUserAuthenticationMethods` communicating which authentication methods the server has suggested will be acceptable. The delegate can then complete `nextChallengePromise` with either a new authentication request, or with `nil` to indicate that the client has run out of things to try.

The server protocol is more complex. The delegate must provide a `supportedAuthenticationMethods` property that communicates which authentication methods are supported by the delegate. Then, each time the client sends a user auth request, the `requestReceived(request:responsePromise:)` method will be invoked. This may be invoked multiple times in parallel, as clients are allowed to issue auth requests in parallel. The `responsePromise` should be succeeded with the result of the authentication. There are three results: `.success` and `.failure` are straightforward, but in principle the server can require multiple challenges using `.partialSuccess(remainingMethods:)`.

### Direct Port Forwarding

Direct port forwarding is port forwarding from client to server. In this mode traditionally the client will listen on a local port, and will forward inbound connections to the server. It will ask that the server forward these connections as outbound connections to a specific host and port.

These channels can be directly opened by clients by using the `.directTCPIP` channel type.

### Remote Port Forwarding and Global Requests

Remote port forwarding is a less-common situation where the client asks the server to listen on a specific address and port, and to forward all inbound connections to the client. As the client needs to request this behaviour, it does so using global requests.

Global requests are initiated using `NIOSSHHandler.sendGlobalRequest`, and are received and handled by way of a `GlobalRequestDelegate`. There are two global requests supported today:

- `GlobalRequest.TCPForwardingRequest.listen(host:port:)`: a request for the server to listen on a given host and port.
- `GlobalRequest.TCPForwardingRequest.cancel(host:port:)`: a request to cancel the listening on the given host and port.

Servers may be notified of and respond to these requests using a `GlobalRequestDelegate`. The method to implement here is `tcpForwardingRequest(_:handler:promise:)`. This delegate method will be invoked any time a global request is received. The response to the request is passed into `promise`.

Forwarded channels are then sent from server to client using the `.forwardedTCPIP` channel type.
