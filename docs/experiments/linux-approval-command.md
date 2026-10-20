# Disposable Linux approval-to-command experiment

This fixture connects the shared approval verifier, consumption/outcome and command-submission
replay tables, audit tables and checkpoint/recovery selection, then launches one fixed ordinary-user
command. It is a component integration experiment, **not a production Linux authority**.
Its schema-4 requester claims and software signing keys are synthetic. It does not claim a
physical phone, biometric operation, hardware key, protected caller, or installed service.

## Reproduce

Use Linux x86_64, Python 3.11 or later, Swift 6.2 or later, SQLite development headers and
library (`libsqlite3-dev` on Ubuntu), and the fixed `/usr/bin/tee` executable. Run without
elevation, differing real/effective credentials, or a sandbox that blocks the fixture's owned
processes and SQLite files. No system policy or installation change is required.
The owned-process cleanup preflight also requires readable procfs task-child enumeration
(`procTaskChildrenReadable` in the caller-monitor prerequisite terminology); missing support
refuses the run before building or launching fixtures.

```sh
python3 scripts/run-linux-approval-command-experiment.py
```

The runner builds `LinuxApprovalCommandFixture` using its committed dependency lock,
four build jobs, and explicit Swift cache/configuration/security/scratch paths. The default
build root is `.build/linux-swift/approval-command`; `--work-dir` accepts an absolute reusable
build root. Each runtime case uses a separate private `0700` temporary directory. Only the
reopen and crash/recovery pairs deliberately share their respective directory.

`--timeout` bounds each fixture process (15 seconds by default, at most 60).
`--build-timeout` bounds the build (600 seconds by default, at most 900).
`--output /absolute/report.json` also saves the sanitized report. Native stdout is capped at
32 KiB and build stdout at 1 MiB while reading; stderr is discarded rather than copied into
evidence. A timeout, malformed report, unexpected exit, or cleanup failure fails the experiment.

The runner hashes its source, cleanup helpers, manifests and dependency locks, plus all source
files from this fixture, the shared host core and Swift protocol, including SQLite headers and
module maps. Host metadata contains numeric kernel, Python and Swift versions and architecture;
it contains no hostname, username, process ID, private runtime path, request content or key.
The inventory is hashed before the build and again after all controls. Changed inputs refuse
the run rather than producing success evidence for a different revision.

## The fixed command and independent execution check

The fixture can launch only:

```text
/usr/bin/tee -a DIRECTORY/command.marker
```

It uses the private directory as cwd and an explicit minimal environment. Its stdin is the fixed
synthetic line `remozio-fixture-output` followed by a newline. The fixture checks the captured
stdout and child exit; the runner independently opens the marker after retiring the entire
fixture process group. Success requires exactly one complete line for successful execution
and no file for a refused request. A duplicate append, partial output, unexpected empty file,
or symbolic link fails this independent check. The marker is not overwritten, so a repeated
launch cannot hide behind equal final contents.

The file check establishes the observed side effect of this reviewed fixture. It is not an
independent attestation that a hostile process executed a particular binary.

## Controls

Every successful native report must contain the exact expected checks, fixed observations,
decision result and state counts. The runner rejects unknown fields, duplicate JSON keys,
numeric values substituted for booleans, unsupported phases and unexpected refusal reasons.
Error text from the native process never enters a published report.
After retiring each worker, the runner also opens SQLite read-only and independently checks
the five expected shared tables, scoped consumption/reservation/outcome/audit row counts,
fixed-size reservation metadata and foreign keys. A native success report or expected crash
cannot substitute for those observations. This is a fixture row check, not protected schema
authentication or a concurrency proof.

| Case | Required decision result | Marker executions |
| --- | --- | --- |
| `approve` | Accepted, one consumption row and successful command result | 1 |
| `malformed-decision` | `malformedDecision` | 0 |
| `malformed-capture` | `malformedCapture` | 0 |
| `bad-signature` | `invalidSignature` | 0 |
| `decline` | `declined`, consumed without execution | 0 |
| `expired` | `expired` | 0 |
| `expire-before-consume` | `expiredBeforeConsume` | 0 |
| `expire-at-shared-consume` | `expiredAtSharedConsume` after tentative reservation; reservation and consumption roll back | 0 |
| `replay` | `replayRejected` after the first execution | 1 total |
| `submission-id-replay` | `submissionIDReplayRejected` for a fresh signed request reusing only the submission ID | 1 total |
| `submission-nonce-replay` | `submissionNonceReplayRejected` for a fresh signed request reusing only the nonce | 1 total |
| `audit-failure` | `auditFailure`, with no reservation, consumption, outcome or audit rows committed | 0 |

The expiry controls inject the retained deadline as the authority moment. The final control
supplies a valid first sample and the exact deadline to the shared consumption call, after
live capture validation and tentative replay reservation in the same transaction. They test
the verifier boundary and consumption-time recheck, rather than waiting for wall-clock
expiration or exercising suspend/resume. Ordinary operations use the Linux authority clock.

After `approve`, a fresh `reopen-completed` process opens the same state and must retain its
successful phase, one consumed request and three audit records without launching again.
Its `outputMatched=false` and absent child exit result mean that the reopened process did
not run a new command; the existing marker must still contain exactly one line. It also uses
the historical reservation metadata to construct two fresh captures and signed requests,
which must be refused for their reused ID or nonce. Old request bytes, software keys and
dispatch tokens are never restored. The collision controls require `alreadyReserved`, so a
capacity error cannot masquerade as replay rejection.

The original fourteen process controls remain, with three added controls for seventeen total.
Consumption and outcome updates use `ConsumptionJournalTables`, and ID/nonce reservation uses
`CommandSubmissionReplayTables`, on the same connection as `AuditJournalTables`. The fixture
owner supplies the outer transaction, capture validation and final clock sample; it issues its
one-use in-memory token only for the incoming verified execute decision. Stored receipts,
outcomes and reservations never reconstruct a dispatch token.

The crash modes intentionally terminate with exit 86 and no stdout. Each crash worker and
its descendants must be retired and reaped before a separate recovery process starts:

| Seed and subsequent process | Expected recovery | Marker executions |
| --- | --- | --- |
| `crash-before-launch` → `recover-before-launch` | Consumed unfinished request becomes `unknown`; pending checkpoint action is `finalizePending` | 0 |
| `crash-after-output` → `recover-after-output` | Consumed unfinished request becomes `unknown`; checkpoint action is unchanged | 1 total |

Recovery must not infer permission to rerun a consumed request from missing or incomplete
execution status. The independently checked append count must stay unchanged. These controls
exercise deliberate process termination at two known fixture boundaries. They do not simulate
arbitrary power failure or certify filesystem durability.

## Cleanup, automation and validation scope

The runner creates a new process group for each worker, becomes a temporary child subreaper,
and uses ownership-aware signaling and adopted-child reaping on success, error, cancellation,
excess output or timeout. Private runtime directories are removed after the case or recovery
pair. This covers the fixture's owned topology, whose children do not escape their process group.
External `SIGKILL` of the runner, malicious process trees and uninterruptible kernel tasks remain
outside that cleanup claim.

`scripts/check-linux-host.sh` retains the existing shared-host test suite and then runs this
fixture with a reusable build root. Consequently both `scripts/check-local.sh` on Linux and
the existing Linux Swift CI job run it. This does not replace any Mac build, interoperability
or live experiment requirement.

Focused portable runner checks:

```sh
python3 -m unittest discover -s tests -p test_linux_approval_command_experiment.py
REMOZIO_LINUX_APPROVAL_COMMAND_LIVE=1 python3 -m unittest discover -s tests -p test_linux_approval_command_experiment.py
```

The ordinary test run exercises report validation, marker duplication/symlink controls,
crash exit validation, private-directory reuse, skipped recovery after a failed seed, fixed
build arguments, source inventories, deadline/refusal behavior and owned-process cleanup.
The environment variable explicitly enables the real fixed-command integration run.

## What remains unproven

The table implementations are shared with the Mac authority. The SQLite connection owner,
configuration file, bounded checksum format and checkpoint-file adapter still belong only to
this fixture. They are not a protected Linux journal, authority protocol, concurrency/locking
implementation or production recovery adapter. The checksum now includes replay rows in its
authority evidence and consumption, outcome and audit rows in its ledger evidence; it is not
the Mac journal continuity format. The software keys do not establish hardware custody or fresh human biometric consent.
The synthetic requester does not establish protected frontend policy, executable provenance,
continuous monitoring or a safe stopped dispatch handoff. The separate
[caller monitor experiment](linux-caller-monitor.md) remains its own evidence boundary.

There is no protected installation, privileged target account, physical phone, enrollment or
network delivery, TPM integration, general command API, PTY, signal forwarding, cancellation
protocol or arbitrary-output streaming path. Passing this experiment demonstrates the stated
disposable approval-to-command mechanics with the existing shared components; the report
uses report version `linux-approval-command-v2`, with `fixtureOnlyOwner=true`,
`sharedConsumptionTables=true`, `sharedReplayTables=true` and `productionAuthority=false`.
Legacy fixture-only-ledger reports are rejected; private fixture stores are recreated, not migrated.
