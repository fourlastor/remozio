# Compiler output overhead experiment

This fork-only experiment follows the hypothesis that frequent compiler progress
messages contribute materially to Mac CI build time. It measures the hypothesis;
it does not change normal check output, remove validation, or assume that quieter
output is faster.

## Existing evidence

The cold Mac job for PR #457, run 39230000879 attempt 1, emitted 22,258 lines
(2,814,114 bytes). Bracketed Swift progress contributed 5,660 lines (444,246 bytes
including log timestamps); 5,479 contained `Compiling`. Ten direct Swift commands
stream through `scripts/check.sh`. Receipt timestamps include buffering bursts,
so neither timestamp gaps nor byte counts establish a logging bottleneck.

The app's Debug and Release Xcode builds already capture their output locally:
26,086 lines / 9,078,521 bytes were retained as artifacts rather than streamed to
Actions line by line. Interoperability builds also capture output. Their measured
cache benefit therefore does not establish a benefit from suppressing progress.

Sources: [cold Mac job](https://github.com/rock3r/remozio/actions/runs/39230000879/job/117985389880)
and [cold interoperability job](https://github.com/rock3r/remozio/actions/runs/39230000879/job/117985389589).

## Controlled comparison

The dedicated `Compiler output benchmark` workflow runs only on
`fourlastor/remozio` when `codex/ci-logging-benchmark` is pushed. It uses one
`macos-26` runner and the real `experiments/release-dependencies` SwiftPM package,
with four build workers and one fixed source checkout.

Six timed builds use the order `stream, file, quiet, quiet, file, stream`.
Every trial restores the same dependency-resolved, compiler-output-empty scratch
state at the same absolute path. Dependency resolution and scratch restoration
occur outside the timed build. A conditioning build runs before the measurements.

| Mode | Compiler verbosity | Output destination | Question |
| --- | --- | --- | --- |
| stream | Normal | Inherited Actions streams | Current progress logging behavior |
| file | Normal | Retained local log | Cost of delivering the same output to Actions |
| quiet | `--quiet` | Retained local log | Additional cost associated with progress generation |

Quiet mode is diagnostic only: its reduced diagnostics must not be adopted in
normal CI without a separate decision. File mode retains warnings and failures.
Every trial must finish successfully and produce comparable compilation work.
The harness records wall time, child CPU, output object inventory and sizes,
command/host/toolchain metadata, and available log sizes. Stream output remains
in the Actions job log; it is not intercepted by a tee process.

The comparison applies to this package and fixed concurrency. It is not a full
CI speedup estimate. Balanced order reduces simple ordering bias but does not
eliminate OS file-cache effects, thermal changes, shared-runner variability or
compiler caches outside the measured scratch directory. Two observations per
mode are a pilot, not strong statistical evidence. Repeat the same workflow if
the pilot suggests a meaningful effect, inspecting variation and compilation
work before changing ordinary workflows.

## Running and retaining evidence

```sh
python3 scripts/benchmark-compiler-output.py \
  --package-path experiments/release-dependencies \
  --output .build/compiler-output-benchmark \
  --jobs 4 \
  --triple arm64-apple-macosx26.0
```

Use a fresh output directory. This command builds disposable outputs; it does not
execute the experiment products, install services, or run privileged commands.
The workflow uploads report JSON and captured logs after measurement, including
failure diagnostics. Compare them with the complete Actions log and exact commit.
Do not interpret a failed or mismatched-work run as a speed result.

No compiler-output overhead result has been measured on a Mac runner yet. The
normal full local gate is required before every benchmark branch push; the
existing upstream warm-cache run remains an independent measurement.
