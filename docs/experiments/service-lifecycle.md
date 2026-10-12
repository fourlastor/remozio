# Protected service lifecycle experiment

The disposable app can exercise Apple's service registration APIs during an interactive session.
It contains an ordinary-account controller, one Aqua agent, one Root daemon and one dedicated-account transport daemon.
It has no keys, listeners, approval RPC or command execution interface.
The production Remozio app does not activate these services.

```mermaid
flowchart TD
    B[Build and safe refusal controls] --> S[Developer ID signature]
    S --> N[Operator notarizes and staples fixture]
    N --> P[Operator creates disposable protected placement]
    P --> G[Controller validates retained paths, manifests and signed code]
    G --> R[Explicit register command]
    R --> A[System approval for daemon]
    A --> L[Verify actual launch, account and code]
    L --> T[Verify dedicated transport account and pre-login launch]
    T --> U[Explicit asynchronous unregister]
    U --> W[Wait for completion]
    W --> C[Protected signed replacement and re-registration]
```

Only the build, synthetic account and refusal controls have run.
The arrows show required evidence, not completed operations.

## Apple API constraints

[SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice) manages helpers inside the calling app bundle.
The installed SDK requires signed apps and notarized apps for launch daemons.
It recommends placement accessible before GUI login.
A daemon needs administrator approval in System Settings before launch.
An agent must be registered in each intended user's context.

Changing a manifest or executable requires re-registration.
Unregister terminates a running helper.
The [asynchronous operation](https://developer.apple.com/documentation/servicemanagement/smappservice/unregister(completionhandler:)) supplies the completion boundary before re-registration.
The production updater must reach its approved idle boundary before unregistering services.
This experiment does not establish that boundary.

## Build without changing services

On Apple Silicon with the macOS 26 SDK or later:

```sh
python3 scripts/check-service-lifecycle.py
```

The script builds an arm64 Swift 6 app, signs it ad-hoc, and deletes its temporary copy afterward.
It checks all three helpers, read-only status, exact manifests, missing confirmation, wrong roles and ordinary-account placement refusal.
It checks ad-hoc signature rejection and rejects altered labels, arguments, account selection and KeepAlive.
It also rejects a transport manifest selecting Root.
It never invokes a confirmed unregister command.
Confirmed register commands run only against its user-owned temporary app and fail before the framework call.
The authority helper refuses ordinary-account service startup before its long-lived path.
The transport helper also refuses its temporary, unprotected startup.
No automated check starts the session helper's long-lived path.

To keep a new Developer ID fixture:

```sh
mkdir -p experiment-results/service-lifecycle
python3 scripts/check-service-lifecycle.py \
  --developer-id '<approved certificate name or SHA-1>' \
  --keep-output experiment-results/service-lifecycle/RemozioServiceLifecycle.app \
  --output experiment-results/service-lifecycle/build.json
```

Existing output paths are refused.
The selected certificate must match the test Team ID `PVDFPZ5D64`.
The script retrieves no credentials and changes no Gatekeeper policy.
The Developer ID checks also verify the publisher and reject the freshly built, unnotarized fixture.
A signing pass does not establish notarization or service eligibility.

The [sanitized evidence](service-lifecycle.json) binds the source hashes and records all unrun platform cases.
The recorded host runs macOS 27.0.1. The deployment target does not prove macOS 26 runtime behavior.

## Dedicated transport account

The experiment uses the fixed account name `_remozio_lifecycle_transport`.
The operator must provision a new dedicated account separately.
The app never creates an account or changes existing account records.
Do not reuse an existing account to make the experiment pass.

The account must use `/usr/bin/false` as its shell.
The resolver reads its UID, primary GID and bounded group list through native account APIs.
It rejects Root, invalid identifiers, and wheel or admin group membership.
The flat group list does not establish nested membership.
It resolves both named groups and uses Apple's [membership API](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/mbr_check_membership.3.html).
That API checks direct and nested membership.
A missing group, conversion error, query error or invalid result refuses registration.
The helper and each registration recheck use the same native checks.
Registration also rejects the invoking GUI account's UID.
It rechecks the same resolved UID, GID and group set immediately before registration.
The transport helper requires that account's actual real/effective UID and primary GID before its service path.

Synthetic controls check valid records and thirteen unsafe records.
They also reject injected nested membership and membership lookup failures.
Read-only native queries run for the current ordinary account.
These controls do not change credentials or prove target-account provisioning or actual nested-group fixtures.
Native lookup does not prove exclusive UID ownership, absence of alternate login methods, or actual launchd group credentials.
Verify those properties separately during the operator session.
A matching username is not proof of isolation.

Removal does not require the account to remain available.
It retains the publisher, manifest and explicit confirmation checks.
This permits cleanup after account loss without claiming that cleanup succeeded.

The transport probe owns no key, listener or provider credential.
The permitted transport-only key fallback remains a separate experiment.
It does not apply to authority or credential-receiving keys.

## Registration boundary

| Check | Requirement |
| --- | --- |
| Operator | Real and effective ordinary UID must match |
| Placement | Root-owned local bundle, every ancestor and every bundled object; no symlinks, hard links or unsafe modes/ACLs |
| Identity | Approved Developer ID chain, Team ID and exact experiment identifiers |
| Runtime | Hardened runtime; no entitlements |
| Notarization | The app must satisfy the native `notarized` code requirement |
| Manifests | Exact fixed labels, executable paths, arguments, account and session settings |
| Account | Transport requires the fixed dedicated account and a fresh identity check |
| Intent | Explicit role and `--confirm-disposable-service-test` |

The placement owner retains descriptors through the synchronous registration call and rechecks named identities.
It reuses Core's protected metadata validator without modifying that validator.
Removal remains reachable after a valid signed test app moves.
It still requires the approved publisher, exact manifests and explicit confirmation.
It waits for the asynchronous framework callback.
An error claims neither successful removal nor safe replacement.

The status value `eligibleNotVerifiedRunning` means eligibility only.
Verify the actual job and source process separately.
Read-only manifest and publisher inspection never grants registration permission.

## Interactive procedure: not run

Perform these steps only with the operator at the Mac.
Select this experiment deliberately. Do not substitute the production authority app.

1. Build and preserve the selected Developer ID fixture. Record its source hashes and code hashes.
2. Submit that fixture through the operator's notarization workflow. Staple and validate the ticket. Preserve the same signed bytes.
3. Choose a new disposable directory beneath an existing protected, boot-accessible local ancestor.
   `/Library/PrivilegedHelperTools/RemozioServiceLifecycleExperiment` is a candidate, not a validated placement.
   Do not change permissions on shared system directories to make a check pass.
4. Use explicit Root authorization to copy only this fixture into that new directory.
   Set the copy and its contents to Root ownership and safe permissions before launching the controller.
   Verify its complete signature again. Keep the source copy for removal if the installed copy becomes unavailable.
5. Run the installed controller as the intended ordinary GUI account. Start with `--status` and `--preflight`.
6. Register the session probe. Verify the actual agent, executable and UID in the intended GUI bootstrap domain.
7. Register the authority probe. Approve only the experiment in System Settings.
   Verify the actual daemon, executable and UID in the system bootstrap domain.
   Separately provision and verify the new transport account, including unique UID ownership and absence of login authority.
   Register the transport probe. Verify its actual signed executable, UID, GID and effective access in the system bootstrap domain.
8. Associate startup logs with that verified process and signed artifact. A matching log string alone is not provenance.
9. Observe lock, logout and a reboot to the login window. Verify transport startup without GUI login.
   FileVault preboot remains outside scope.
10. Unregister each exact experiment role. Wait for the controller's successful asynchronous result.
    Verify that the exact job and process are gone before replacing the fixture.
11. Copy a second protected, signed and notarized build. Re-register from the intended account and repeat process verification.
12. Remove only the exact experiment jobs and owned copies.
    Remove the dedicated account only after verifying ownership and that no experiment process remains.
    Preserve evidence and report uncertain cleanup separately.

Example commands after protected placement and notarization:

```sh
# Replace this path with the verified installed fixture. Run as the ordinary GUI account.
TASK_PROBE_APP='/Library/PrivilegedHelperTools/RemozioServiceLifecycleExperiment/RemozioServiceLifecycle.app'
"$TASK_PROBE_APP/Contents/MacOS/RemozioServiceLifecycle" --status
"$TASK_PROBE_APP/Contents/MacOS/RemozioServiceLifecycle" --preflight
"$TASK_PROBE_APP/Contents/MacOS/RemozioServiceLifecycle" --register session --confirm-disposable-service-test
"$TASK_PROBE_APP/Contents/MacOS/RemozioServiceLifecycle" --register authority --confirm-disposable-service-test
# Only after separately provisioning and verifying the experiment account:
"$TASK_PROBE_APP/Contents/MacOS/RemozioServiceLifecycle" --register transport --confirm-disposable-service-test
# Later, after collecting evidence and closing the test session:
"$TASK_PROBE_APP/Contents/MacOS/RemozioServiceLifecycle" --unregister session --confirm-disposable-service-test
"$TASK_PROBE_APP/Contents/MacOS/RemozioServiceLifecycle" --unregister authority --confirm-disposable-service-test
"$TASK_PROBE_APP/Contents/MacOS/RemozioServiceLifecycle" --unregister transport --confirm-disposable-service-test
```

Helpers log only role, numeric UID and startup/termination messages through Unified Logging.
They read no credentials or command input.
Their service mode waits for termination and can consume resources until removed.
Do not use that mode as an ordinary build smoke test.

## Remaining gates

Registration, Root placement, notarized acceptance, reboot, replacement and actual removal have not run.
The transport role is prepared, but actual dedicated-account behavior and pre-login access remain untested.
Pre-login hardware key access still needs a separate fixture and evidence.
This app grants no production activation, anti-rollback, installer, enrollment or update-quiescence proof.
Use the [interactive handoff](interactive-handoff.md) to retain those requirements.
