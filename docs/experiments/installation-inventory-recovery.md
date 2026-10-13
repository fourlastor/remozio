# Installation inventory process recovery

The experiment uses the actual `PreparationIntentStore` and its machine writer lease.
It creates only ordinary-owner private files with synthetic metadata.
It never installs a service or opens protected Root storage.

```mermaid
sequenceDiagram
    participant P as Parent fixture
    participant C as Child writer
    participant D as installation.sqlite
    P->>D: Initialize, explicitly upgrade, retain inventory and preparation
    P->>C: Try a second writer while the lease is held
    C-->>P: Refused as busy
    P->>C: Replace inventory after releasing the lease
    C->>D: Commit the replacement
    C--xC: Exit without Swift finalizers
    P->>D: Reopen and compare retained state
    P->>C: Replace again
    C->>D: Commit
    C-->>P: Signal the test-only post-commit boundary
    P--xC: SIGKILL the owned child
    P->>D: Reopen; require replacement and original preparation
```

## Run the controls

Use an ordinary Apple Silicon macOS account:

```sh
python3 scripts/run-installation-inventory-experiment.py --output experiment-results/installation-inventory.json
```

The runner compiles for macOS 26 and hashes all repository code inputs.
These include the full Core and Protocol source trees, package manifests and dependency locks.
Third-party revisions are pinned by the locks. SDK and toolchain bytes are outside this source attribution.
It enables test visibility only in the experiment dependency build, not the shipped app.
This permits the existing internal ordinary-owner lease seam.
The public store API still requires real and effective Root identity.

The three controls require writer exclusion across processes, retention after `_exit`, and retention after SIGKILL following commit.
Both recovery cases compare the new inventory revision and bundle path.
They also require the original preparation record to survive.
Success requires private fixture removal.

The parent owns its child processes and uses bounded fixture waits.
Each child joins the runner group before storage access.
The SIGKILL boundary verifies that membership, so runner cancellation includes the paused child.
The runner also bounds compilation and execution, killing its owned process group on interruption or timeout.
These are experiment limits, not deadlines for approved commands or requests.

`./scripts/check.sh` includes the probe on macOS.
Its observed runtime is reported separately from its deployment target.
The local macOS 27.0.1 run passed; it does not establish macOS 26 behavior before CI runs.

## What remains unproven

The fixture uses an ordinary-owner lease and synthetic Root-role metadata.
It does not prove protected Root ownership, installed service isolation or complete installation inventory.

Both death cases follow successful SQLite commit.
They do not prove power-loss durability, native I/O fault recovery or interrupted writes before commit.
They create no hardware keys, pairing, enrollment grants, approvals, service registration or activation.
The earlier separate-database prototype remains distinct from this actual-store experiment.
