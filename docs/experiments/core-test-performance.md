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
