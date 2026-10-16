# Authority maintenance

`AuthorityService` can run a serial maintenance timer after the listener starts.
The timer stops before the journal closes.
Explicit closure waits for any active maintenance callback.
If a sweep or reconciliation fails, the service retires the timer and closes instead of continuing to serve.

The expiry initializer samples the supplied authority clock inside `AuthorityJournal.withRequests`, calls `expirePending`, and reconciles the committed results before releasing the journal lock. The receipt time is optional audit metadata and never controls expiry.

```mermaid
flowchart LR
    Timer[Serial timer] --> Lock[Acquire journal lock]
    Lock --> Clock[Sample authority clock]
    Clock --> Sweep[Commit expiry sweep]
    Sweep --> Reconcile[Reconcile delivery withdrawals]
    Reconcile --> Unlock[Release journal lock]
    Sweep -->|failure| Close[Close authority service]
    Reconcile -->|failure| Close
```

The interval defaults to one second and accepts 100–60000 milliseconds. A timer tick is a prompt to check deadlines, not the deadline clock. Startup must supply the same sleep-inclusive clock epoch used for admission. Callbacks are synchronous and must not reenter the service or journal. Reconciliation must arrange delivery withdrawals; a failure after a successful audit commit does not undo the committed expiry.

The current trust-only executable does not enable maintenance or admit requests. Startup can construct `AuthorityClock` once and share its epoch with request owners. Pass `{ try clock.now() }` as the expiry clock. Delivery ownership and recovered request admission remain startup integration work. No root service or device was installed by these tests.

Tests cover interval bounds, closure before start, failure retirement, repeated start rejection, and closure waiting for active work. Existing service tests verify storage release and failed startup.

## Production clock

`AuthorityClock` reads `mach_continuous_time`, so elapsed time includes sleep. Each public construction creates a fresh authority epoch; copies preserve it. Startup must share one instance across admission and expiry and replace it after an authority restart. Persisted request recovery must not reuse an old epoch.

Conversion uses a full-width integer product and floors to milliseconds. Invalid timebase values and an unrepresentable result throw. Wall time never participates in this conversion. Existing request owners still reject clock regression and epoch mismatches. Gateway delivery uses the same conversion with its configured epoch.

Tests cover fractional boundaries, a product larger than 64 bits, overflow, invalid timebases, and live monotonic samples. They do not establish suspend/resume behavior on a physical Mac; that remains in the device test handoff.
