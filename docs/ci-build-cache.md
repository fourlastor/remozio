# Mac CI build caches and measurement

The Mac build and interoperability jobs retain compiler outputs between compatible
runs. Every build command, native experiment, test, signature/bundle inspection,
and interoperability check still runs. A cache hit is never a passing check.

## What is cached

`scripts/ci-build-cache.py` lists the SwiftPM scratch directories used by the Mac
gate, including the release-signing scratch directory, and the packaging and app
Xcode DerivedData directories. The System Keychain experiment's `.build` is included
with the other Mac SwiftPM outputs. Interoperability has its own cache containing its
SwiftPM peer build directory. The jobs do not cache the entire repository `.build`
directory: disposable experiment state, reports, copied peers and logs are excluded.
The peer builder still copies newly validated binaries before Gradle starts.

The compatibility prefix includes the job scope, resolved checkout path, CPU
architecture, macOS build, runner image version, Xcode/Swift/Clang versions,
developer directory, SDK path/version/build, build-related environment settings,
and hashes of the build scripts, workflow, package manifests/lockfiles and Xcode
project settings, except the exact audited Linux-only inputs described below.
A changed compatibility dimension starts a cold namespace.
The exact key additionally hashes all tracked input bytes and modes. A compatible
prefix restore can reuse outputs from another source revision.

The cache contains a matching input manifest. After restoring outputs, unchanged
regular files regain their exact recorded nanosecond modification times, only
after their content hashes and modes match. Changed inputs are not backdated.
Added/deleted/renamed build inputs, file-type changes, or a changed input whose
timestamp collides with its old timestamp discard the explicit output roots and
build cold. The file-set comparison exempts regular, non-executable `.md`
files under top-level `docs/`, with no special permission bits. The cached native
builds do not consume this documentation tree. Markdown elsewhere (including
package resources), symlinks and executable documentation remain conservative.
Both the old and new inventories are classified, so changing an ordinary document
into one of those inputs, or back, still requires a cold build. A future build that
consumes `docs/` must revisit this policy.

The second narrow exemption is the helper's explicit `LINUX_ONLY_INPUT_MODES`
table: 47 existing files in the Linux approval-command, composed caller-command,
OS-capture, pairing-peer, native-TPM/TLS, caller, caller-monitor, storage-lease and
TPM/TLS experiments, plus their 11 dedicated Linux check/coordinator/runner scripts.
A repository test requires every entry to be tracked at its recorded mode, so a move
or deletion fails instead of silently narrowing the table. These exact regular files, at their recorded
expected modes, are omitted only from native compatibility settings and discovery
invalidation. There is no `linux-*` prefix or directory exemption: an unknown new
path, even inside one of those Linux packages, stays conservative. Both old and new
inventories are classified, so type or unexpected-mode transitions still build cold.

The dependency audit finds no Mac SwiftPM/Xcode graph consuming those experiment
files. The Linux packages depend on shared protocol/core and on each other (the
composed fixture uses the approval-command and OS-capture libraries), with no reverse
dependency. Only the Linux Swift job and the Linux branch of `check-local.sh` build
or run them; the Mac native gate invokes none of the 11 Linux entry points.
Portable Python tests may import/test the runners or use owned temporary workers;
those checks still execute on every cache hit and produce no cached Mac/interop
compiler output. Shared protocol/core, `generate-linux-capture-fixtures.py`, Mac
build scripts, the cache/smoke helpers, `check.sh`, `check-local.sh`, and every
workflow remain sensitive. Workflow edits confined to Linux jobs still start a
cold compatibility namespace. If a future Mac build consumes an exempt input,
revisit the table; do not extend it without auditing dependencies.

Documentation and the audited Linux inputs remain in the exact content key,
manifest, byte/mode/type checks, timestamp checks and save-stability check. Thus a change can reuse a compatible-prefix
cache but cannot masquerade as identical input. Even a changed document with its
old timestamp still triggers the conservative collision fallback. Symlink targets
are not timestamped. Missing, incompatible or malformed manifests also cause a
cold build. Source directories retain their checkout timestamps.

Successful jobs save a new manifest only if the tracked byte/mode inventory stayed
unchanged during validation. A changed lockfile or generated tracked input prevents
saving under the original key. Cache transfer failures fall back to regular builds;
cache saving is an optimization and cannot turn failed validation into success.
GitHub's normal cache branch/ref isolation applies; no shared privileged cache or
`pull_request_target` execution is introduced.

The timestamp approach follows Swift's observed incremental behavior: a timestamp
change can rebuild identical source bytes, including when the new time is older.
Restoring the exact previous timestamp avoids that unnecessary change. Actions'
cache archive uses POSIX extended tar format, which retains subsecond output times.
See the [cache action](https://github.com/actions/cache) and
[archive implementation](https://github.com/actions/toolkit/blob/main/packages/cache/src/internal/tar.ts).

## Correctness control

Run `python3 scripts/check-swift-cache.py` with Swift 6.2 or newer. The Mac build
job runs it before the full native gate. It creates a disposable package, then:

1. Builds cold and executes its test and executable.
2. Archives build outputs and the input manifest, recreates source files with a
   fresh Git checkout at the same absolute path, restores the archive and exact
   unchanged-source timestamps, and checks that no source frontend command runs.
   The test and executable must execute again and return the original value.
3. Adds, edits, renames and removes a tracked documentation report, comparing each
   phase with the previous validated inventory. Every phase must preserve source
   timestamps, avoid source frontend compilation, and execute the test and binary.
4. Changes source bytes without changing their size and checks that rebuilt code
   and a freshly executed test return the new value.
5. Repeats with a deliberately colliding old timestamp, requiring the conservative
   cold-build fallback and another changed runtime result.

Between the documentation and source controls, three additional stages add, edit
and remove an exact audited Linux manifest/source pair. Each changes the full
content inventory while preserving compatibility settings, restores identical
source timestamps, performs no source frontend compilation, and executes both the
test and executable again. These are eligibility/correctness controls for the
disposable package, not a Mac cache hit or full-job timing claim.

The JSON report and verbose logs are written under `.build/ci-cache-smoke` and
uploaded with the Mac app build logs, including on failure. This is a small
dependency-free correctness control. It does not establish Xcode DerivedData reuse
or predict the full job's speedup. Linux success is not a Mac result.

## Measure the actual CI benefit

The cache helper reports exact/prefix/missing restoration, matched and changed
inputs, preparation duration, and output bytes in the job summary. Each gate stage
prints its duration and exit status. Captured Swift and Xcode builds report their
own durations separately from the surrounding inspection or experiment.

After opening the CI PR, retain two successful runs of the same head:

1. Record the first cold-cache Mac build and interoperability jobs, their runner
   and toolchain identities, full job durations, stage times, cache size and cache
   save duration. All required checks and the cache smoke must pass.
2. Rerun those jobs on fresh runners after the successful caches are saved. Verify
   exact cache hits and matching compatibility keys. Record restore time, stage
   times and full job durations; all tests and inspections must run again.
3. Compare net job time including cache transfer, rather than only compiler time.
   If restore/upload overhead or Xcode invalidation removes the benefit, adjust
   the cache scope before claiming an improvement.
4. Inspect the smoke's ordinary-edit and timestamp-collision controls on the Mac
   runner. Confirm a real source edit in the PR also rebuilds its affected target.

No measured full-job improvement is claimed until those Mac runs exist. The prior
Mac baseline on PR #446 took about 45 minutes, with substantial time in both
compilation and tests; a later run had a larger base-branch test suite. Compare the
same revision and runner image instead of using those different suites as a cache
speed comparison. Native Mac build and interoperability remain merge requirements.

## Documentation invalidation follow-up

[PR #461's Mac build](https://github.com/rock3r/remozio/actions/runs/39271173794/job/118123548286)
restored a compatible main-branch cache successfully, then discarded its compiler
outputs with `cold-input-change`. The tracked delta was two modified protocol
files and the added `docs/experiments/cbor-major-dispatch.md` report; compatibility
settings matched. The report addition alone made the old all-paths discovery
comparison fail. The same decision occurred in the interoperability job.

The documentation exception addresses that observed invalidation. It does not
exclude documentation from integrity checks or make arbitrary source-graph changes
incremental. This helper change itself starts a new compatibility namespace, so
the first CI run may be cold. Passing the disposable smoke demonstrates reuse and
correctness only for that package; a reduction in the full Mac job's duration
still needs native CI evidence. No additional whole-job timing claim follows from
this change, and all existing builds, tests and interoperability checks still run.
