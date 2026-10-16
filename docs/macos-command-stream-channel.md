# Authenticated local command streams

Wire version 4 carries ordered command input and output through input carrier 4.
Both peers must offer version 4 explicitly.
Legacy offers keep their existing behavior.

The CLI retains the original Root handshake and admitted request. A new private control queue belongs to that request alone.

```mermaid
sequenceDiagram
    participant CLI
    participant Root
    CLI->>Root: Negotiate wire 4; submit original descriptors
    Root-->>CLI: Admit the bound request
    Note over Root: The native execution owner remains a separate gate
    Root-->>CLI: Open the stream; transfer its private control right
    CLI->>Root: Bounded input, signal, resize, cancellation
    Root-->>CLI: Ordered output and input credit
    Root-->>CLI: Output EOF
    CLI->>Root: Acknowledge consumed output
    Root-->>CLI: Original terminal result
```

The diagram shows the channel contract. The [connected PTY pump](macos-command-pty-pump.md) now joins the transport owner to native execution.

## Binding and ownership

Every frame contains the negotiated profile, submission ID, submission nonce, submission digest, and original admitted request identity.

The receiver checks the actual kernel sender and its current code policy. It also requires the original process incarnation. Another accepted code identity cannot reuse that binding.

The frontend checks every event against its retained Root process. A ready event must carry exactly one private control right. Other stream events carry no rights.

The receive owner remains the queue's sole consumer. Imported rights stay owned through transfer, failure, and closure. Stream closure neither signals a process nor grants another execution.

## Bounds and ordering

Each frame contains at most 4096 data bytes. Its complete canonical payload has an 8192-byte limit. Each private queue holds at most four messages.

Each direction has its own monotonic sequence. A successful send advances it once. Queue saturation and send interruption preserve the sequence and original unsent body.

The frontend starts with 32768 bytes of input credit. Successful input sends consume that credit. Valid credit events restore only the outstanding amount.

The native pump must enforce the same credit before retaining input. It must restore credit only for consumed input. It must keep its input and output buffers bounded.

Input EOF prevents more input bytes. It leaves signal, resize, cancellation, and output acknowledgment available. Output EOF ends the output sequence.

The frontend acknowledges output after it consumes the bytes. The authority exposes that acknowledgment for its finish controller. This prevents a full output queue from losing the single terminal reply.

A detached wire 4 stream can still return the original authenticated native result with an explicit interruption marker.
The marker is optional terminal field 7 with value 1. It is valid only for wire 4 after the stream opened.
Absence keeps the normal EOF and output acknowledgment requirements. Other marker values and unknown fields fail closed.
The public result exposes `outputInterrupted` separately from the native outcome. The interruption grants no retry authority.
Known send timeouts or interruptions retain the exact terminal packet and original reply right. Only delivery is retried after queue capacity returns.
Successful delivery or a permanent transport error retires that right. The dispatcher keeps no additional execution permission.
Wire 3 and normal terminal envelopes keep their existing bytes. This wire 4 extension precedes product deployment.

Stream messages never establish an exit or authorize release. The native process owner and durable journal remain the sources of those facts.

## Current integration boundary

The native dispatcher supports wire 4 PTY execution and retains wire 3 pipes. Wire 4 pipes still fail before spawning.
[Wire 6 job observations](macos-command-job-events.md) extend PTY streams through an explicit offer.
They remain valid after output EOF without reopening output bytes.
[Wire 5 pipe controls](macos-command-pipe-controls.md) add signals and cancellation without PTY stream meanings or output acknowledgment.

The connected pump enforces native controls, continuous drain, final acknowledgment, and the captured disconnect behavior.

The CLI executable must restore its original terminal settings on every exit. It must read no input before admission and the opened event.

No approved command gains a hidden runtime limit. An empty stream poll only ends that poll. A disconnect never resubmits a command.

## Evidence

Codec tests cover explicit negotiation, exact request binding, binary bytes, direction, limits, replay, gaps, and EOF ordering.

Kernel tests cover private control rights, full queues, retry without sequence loss, actual signed sender rejection, ordered output, and drain acknowledgment.

The CLI test verifies signal, resize, input, input EOF, cancellation, output, and the original terminal result. These tests do not signal a privileged child.

The disposable cross-process probe transferred 524288 bytes in each direction for each of ten trials. Each trial rejected another process with the same signing identifier.

That probe used one-slot queues and a 4096-byte pending buffer. Its parent observed 18 queue timeouts in total. All child processes exited with status zero and were reaped.

The minimum build target was macOS 26 on ARM64. The measured runtime was macOS 27.0.1. The retained evidence contains no secrets.

Still unproven: installed Root service, cross-user policy, actual macOS 26 runtime, real frontend terminal restoration, and physical device tests.
