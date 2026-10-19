# Core test performance investigation

The successful cached Mac run for PR #457 spent 1,206 seconds executing 2,823
core tests (one skip). Nine `GatewayRuntimeActivationOperationTests` accounted
for 466 seconds; the six-stage interruption/retry test alone took 201 seconds.
These are observed test durations, not a diagnosis of the underlying cost.
Source: [cached Mac run](https://github.com/rock3r/remozio/actions/runs/39230000879/job/118019506037).

The first fork-only `Core test profile` run built the tests separately, then ran
all nine cases serially with opt-in aggregate wall-time, process-CPU and call-count
observations. Timings distinguish fixture setup, retained machine-store access,
file publication/validation and the operation itself. Nested intervals are
inclusive: their totals must not be summed as independent time. The profile uses
real owned SQLite files and preserves every assertion, fresh interruption fixture,
retry order and durability setting. It does not register native services or invoke
privileged operations. Ordinary CI remains unchanged.

Profiling is enabled only by `REMOZIO_TEST_PROFILE_DIR`. The workflow retains host,
compiler, test and aggregate profile evidence, including failure logs. The first
run is diagnostic, not an optimization or a before/after speed claim. Any change
must retain the existing ownership, durability and interruption coverage, and be
measured on a supported Mac. Blanket parallelism is not assumed safe: other core
tests change process-wide signal handlers or umask. No timeout or assertion is
weakened by this experiment.

## First native profile

[Run 39246629242](https://github.com/fourlastor/remozio/actions/runs/39246629242)
on revision `1b2e729e4be4365ca1f2eb572162581772e8aa0d` passed all nine tests
without skips in 409.848 seconds. The host was arm64 macOS 26.6.2 (25G83),
Xcode 26.6 (17F113), Swift 6.3.3. All 627 recorded spans had valid CPU readings.

| Inclusive category | Calls | Wall seconds | Process CPU seconds |
| --- | ---: | ---: | ---: |
| Top-level fixture setup/close | 112 | 2.910 | 1.933 |
| Machine store open | 302 | 0.162 | 0.159 |
| Machine store body | 302 | 406.614 | 400.940 |
| Machine store close | 302 | 0.017 | 0.017 |
| `files.verifyCurrent` | 16,342 | 381.528 | 376.364 |
| Injected `run.verifyScope` | 33,707 | 0.044 | 0.043 |

These rows overlap. In particular, the file verification callbacks execute inside
machine bodies; adding them would double-count time. The callbacks themselves
accounted for about 93% of the test interval. Process CPU was close to elapsed
time, while fixture setup and store open/close were small. This points to repeated
retained-state computation as the next measurement target; it does not attribute
the cost to a particular decoder, cryptographic operation, syscall or durability
setting. The earlier 466-second class run is not a matched optimization comparison.

The next diagnostic uses `scripts/profile-core-test.py` to run just the existing
complete-operation XCTest method, through the resolved native XCTest loader.
It samples that exact owned child PID for ten seconds after a two-second delay.
The loader and sampler have bounded lifetimes; no process search, system-wide
trace, privilege change or memory dump is used. Test output and exit status,
wall/child CPU, sampling status and the stack text are retained. Sampling failure
fails the diagnostic without hiding the actual test result. This is another
measurement, not a change to the production verification sequence.

## Owned stack sample

[Run 39249168553](https://github.com/fourlastor/remozio/actions/runs/39249168553)
on `d202c966e22688c1b8773631e8efd7a77ba13ad2` sampled the unchanged
complete-operation method and passed its single selected test in 58.232 seconds.
The sample targeted the recorded owned XCTest PID, covered ten seconds of its
early execution, and retained 6,714 main-thread observations. This instrumented
run is not a timing baseline: sampling adds overhead and does not cover every
phase of the test.

Counting each observation once per function (without recursive double counting),
`loadRuntimeActivation` appeared in 38.8% of main-thread observations, CBOR decode
in 23.0%, CBOR encode in 21.2%, XPC policy construction in 22.1%, and native
requirement parsing in 10.7%. These paths overlap. The evidence points toward
repeated canonical plan reconstruction, not fixture setup or SQL execution as
the dominant cost. No scope check or durability setting has been removed.

## First bounded computation experiment

The first candidate replaces the CBOR reader's temporary five-element array and
`contains` call with an integer switch at the same point in parsing. The sampled
stacks directly include allocation and generic collection work at that line.
The allowed major types, special simple-value handling, argument parsing order,
limits and error precedence remain unchanged. New regressions exhaust unsupported
major-type headers and the accepted major-7 headers; all existing vectors and
malformed-input checks continue to run.

A standalone debug-build A/B benchmark compares the exact baseline decoder with
this candidate on fixed synthetic scalar-heavy and nested canonical inputs. It
builds outside timing, warms both executables, alternates balanced trial order,
and retains input hashes, result checksums, raw timings and toolchain details.
These are synthetic decoder measurements, not retained-state or full-suite
speedups. A native test-class comparison is required before attributing any
check-time improvement to this change. Memoizing plans or policy decisions is
outside this first experiment.
