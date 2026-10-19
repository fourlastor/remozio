# Control optional delivery without replacing the Root service

An explicit settings change binds the previous commit, selected commit and exact revision digest.
Ordinary optional installation still refuses a changed commit.
Quiescence stops new phone registration work and drains the existing journal owner.
The Root service then cancels and joins optional wake publication.
It keeps foreground requests, their deadlines, pairing state and the original Root epoch.

```mermaid
sequenceDiagram
    participant S as Pinned Setup controller
    participant R as Existing Root service
    participant P as Optional publisher
    S->>R: Authenticate and bind exact change
    R->>R: Fence and drain phone registration
    R->>P: Cancel and join publication
    R-->>S: Suspended for this Root epoch
    Note over S,R: Setup must verify files and both native consumers separately
    S->>R: Accept exact successor and same epoch
    R->>P: Permit a fresh protected load
    R-->>S: Accepted; phone health remains unproven
```

The protocol uses deterministic bounded messages with an exact field set.
A fresh challenge and Root epoch bind each response to its request.
The native listener accepts only pinned Setup code running as Root.
The native client checks the current Root code, release declarations and expected epoch.
Each call has a deadline. Cancellation and disconnect close the channel without retrying an uncertain mutation.
The listener joins retired work before the journal can close.

Signed declarations advertise control version 1 only for Root and Setup.
They preserve the earlier preparation schemas and retained record format contracts.
Actual Debug and Release artifact checks compare these declarations with compiled contracts.

Owned journal, in-process service and anonymous XPC controls cover the mechanism.
They do not prove production Root identity, Developer ID admission or installed service registration.
Codec 3 explicitly retains the Root endpoint flag. Legacy codec 1 and 2 retain their old behavior.
The fixed Root job declares its account-specific Mach service only when that flag is enabled.
The runtime listener starts beside the existing Root service and closes before its journal.
Gateway metadata reconstruction preserves the flag.
Both native consumers, restart reconciliation, fresh host selection and the app action follow separately.
No app action exposes this internal endpoint yet.
No installed services, production secrets, physical devices or frozen recovery artifacts are used for these checks.
