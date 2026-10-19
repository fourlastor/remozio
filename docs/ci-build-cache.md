# Mac CI build caches and measurement

The Mac build and interoperability jobs retain compiler outputs between compatible
runs. Every build command, native experiment, test, signature/bundle inspection,
and interoperability check still runs. A cache hit is never a passing check.

## What is cached

`scripts/ci-build-cache.py` lists the SwiftPM scratch directories used by the Mac
gate, including the release-signing scratch directory, and the packaging and app
Xcode DerivedData directories. Interoperability has its own cache containing its
SwiftPM peer build directory. The jobs do not cache the entire repository `.build`
directory: disposable experiment state, reports, copied peers and logs are excluded.
The peer builder still copies newly validated binaries before Gradle starts.

The compatibility prefix includes the job scope, resolved checkout path, CPU
architecture, macOS build, runner image version, Xcode/Swift/Clang versions,
developer directory, SDK path/version/build, build-related environment settings,
and hashes of the build scripts, workflow, package manifests/lockfiles and Xcode
project settings. A changed compatibility dimension starts a cold namespace.
The exact key additionally hashes all tracked input bytes and modes. A compatible
prefix restore can reuse outputs from another source revision.

The cache contains a matching input manifest. After restoring outputs, unchanged
regular files regain their exact recorded nanosecond modification times, only
after their content hashes and modes match. Changed inputs are not backdated.
Added/deleted/renamed inputs, file-type changes, or a changed input whose timestamp
collides with its old timestamp discard the explicit output roots and build cold.
Symlink targets are not timestamped. Missing, incompatible or malformed manifests
also cause a cold build. Source directories retain their checkout timestamps.

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
3. Changes source bytes without changing their size and checks that rebuilt code
   and a freshly executed test return the new value.
4. Repeats with a deliberately colliding old timestamp, requiring the conservative
   cold-build fallback and another changed runtime result.

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
