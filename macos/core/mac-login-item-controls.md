# Main app login controls

`MacLoginItemControls` owns one main-app login registration on the UI actor. The production driver uses `SMAppService.mainApp`. The app owns the controller across Settings recreation. Services never construct it.

```mermaid
flowchart LR
    U[Settings action] --> C[App-owned login controller]
    C --> S[macOS main app registration]
    S --> R[Read current status]
    R --> UI[Toggle and pending approval message]
    UI -->|Explicit button| L[Login Items settings]
```

The toggle represents registration, including registration awaiting user approval. Only the enabled state reports eligibility. Not-found and unknown states never claim registration. Refresh cannot overwrite state during an outstanding operation. Concurrent actions do not start another mutation. Every completed operation rereads system status, including errors. A failed-enable notice clears only after enabled status is confirmed. A failed-disable notice clears only after confirmed unregistration. Unknown and pending states preserve an unresolved failure.

No change runs during construction or refresh. Pending approval does not trigger another registration or open System Settings. The explicit settings button opens Apple's Login Items panel. This controller changes no authority, enrollment, request or privileged-service state.

Apple's installed `SMAppService.h` states that main-app registration affects subsequent logins. Main-app unregistration leaves the running app alive. Other helper unregister operations can kill their services; this controller is not the privileged update mechanism.

Eight fixture tests cover pending approval, external consent revocation, failed registration, failed removal, concurrent operations, unknown states and explicit navigation. The native view typechecks against macOS 26. Actual system registration, login and accessibility remain unproven until the interactive session.

The two notice-recovery regressions failed before this fix. Both now require recovery without another registration or removal.
