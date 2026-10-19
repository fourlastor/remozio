# Join direct Transport work before shutdown completes

The outer Transport owner must join handlers and refresh work before releasing its lifetime.
Stopping admission or cancelling a task does not prove that work has finished.
A reserved task also remains pending until its actual task is installed and terminates.

```mermaid
flowchart LR
    A[Close admission] --> C[Cancel current and retired listeners]
    C --> H[Join every reserved handler]
    C --> F[Abort and join trust refresh]
    H --> J[Confirm all work settled]
    F --> J
    J --> B[Release connection budgets once]
    B --> L[Return to the outer lifetime owner]
```

Each listener owns its pending task handoffs and shared connection budget.
A late task installation inherits cancellation. An empty reservation cannot satisfy a join.
Concurrent and cancelled closers still wait for actual completion.
Trust replacement retains old listeners until their handlers finish.
A replacement listener shares the connection budget with those retained handlers.
Trust refresh work and its timer also remain owned until they finish.

Immediate close remains available to internal handlers. A handler must never join itself.
External lifetime owners use closeAndWait. The existing Transport entry point now uses that joined path.

Controls cover delayed task installation, cancellation, retired listeners and concurrent closers.
An owned native loopback control closes an unfinished TLS handshake and checks that its budget is released once.
These checks use disposable keys and local fixtures. They do not establish installed service or physical phone behavior.

Native settings hosts will use this joined foreground adapter next.
Their later Transport entry must preserve the existing joined shutdown change.
No installed services, production secrets, physical devices or frozen recovery artifacts are used for these checks.
