# Core test performance investigation

The successful cached Mac run for PR #457 spent 1,206 seconds executing 2,823
core tests (one skip). Nine `GatewayRuntimeActivationOperationTests` accounted
for 466 seconds; the six-stage interruption/retry test alone took 201 seconds.
These are observed test durations, not a diagnosis of the underlying cost.
Source: [cached Mac run](https://github.com/rock3r/remozio/actions/runs/39230000879/job/118019506037).

The fork-only `Core test profile` workflow builds the tests separately, then runs
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
