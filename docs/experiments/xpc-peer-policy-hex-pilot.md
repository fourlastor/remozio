# XPC peer policy hexadecimal conversion pilot

This fork-only diagnostic isolates the reviewed lowercase hexadecimal conversion change in `XPCPeerPolicy.swift`. It is prepared for native measurement; no native result is claimed here. The baseline is main `72744baa263ce6d8c8685972d9f7be87d381ee42`, with baseline source SHA-256 `0175c98e2f253b674fb8d0aade6d8e2cde36c859dd20ef10af38b1268ce50c01` and candidate source SHA-256 `733b03399f655bb225d01215e86066b8444a49abe288e573e531a36c3e491792`.

The class driver selectively adapts `scripts/benchmark-core-tests.py` from diagnostic commit `26434d82715ce61951f1ea708781a56455974a74`. It retains serial fresh XCTest processes, the same checkout and SwiftPM scratch path, actual primary-file compiler evidence, binary/object hashes, fixed tracked-input inventories, per-case output, wall and child CPU time, bounded owned workers, and restoration of changed source bytes/mode/mtime. It does not import historical profile instrumentation or overwrite current fixtures.

## Execution plan

Use a separate clean, owned fork branch based exactly on the baseline, with only the reviewed two-file candidate and the explicit allowlist of audited non-native cache/diagnostic files. Run the candidate's native `XPCPeerPolicyTests` before timing. Those tests verify all-byte and 20-byte slice parity plus complete policy requirement text and parsing; do not substitute a portable formatter-only check for native policy validation.

Then run exactly one four-observation ABBA pilot:

```sh
swift test --package-path macos/core --triple arm64-apple-macosx26.0 --jobs 4 --force-resolved-versions --filter XPCPeerPolicyTests
python3 scripts/benchmark-xpc-peer-policy-tests.py --repo "$GITHUB_WORKSPACE" --order abba --output .build/xpc-peer-policy-hex-pilot/class-abba
```

Keep command exit status and complete native parity output. Retain the whole output directory, including failure logs, with an always-upload workflow step. Use the existing fork restriction, macos-26 runner, read-only contents permission and pinned Actions. The root task owns the combined `.github/workflows/ci-performance-pilot.yml` workflow and publication; this document is invocation guidance only.

The driver only accepts the frozen source and candidate parity-test hashes. It rejects branch changes outside the two candidate files and the explicit audited non-native allowlist. Every other native source, package, fixture and test stays at the pinned main revision. It temporarily holds `XPCPeerPolicyTests.swift` at its original main bytes for BOTH timed variants because new parity cases call the new helper, which does not exist in the exact baseline. It restores both candidate files after normal completion or an exception, and refuses to overwrite an unexpected concurrent edit. The nine `GatewayRuntimeActivationOperationTests` cases and every fixture/production input other than the reviewed policy source remain identical between trials. Existing assertions, durability operations, interrupted-stage loops and fixture lifecycle are unchanged.

The timed command runs the complete nine-case class, never a sampled subset. Every case must start and pass exactly once, in the same order across trials, with zero skips/failures and an exact nine-test summary. The source must actually compile on variant changes; only an immediately previous identical source/object/bundle may reuse an already proven build. Compilation, inventory checks and metadata capture are outside timed XCTest execution. Added parity tests are never counted among the nine Gateway cases.

## Budget and stopping rule

The minimum meaningful native pilot is four full-class observations: A, B, B, A. Historical runs place this class around seven to eight minutes, so allow roughly 30–35 minutes for measured executions plus native parity, cold build and metadata: a 60-minute job is a practical normal budget, with explicit driver limits of 600 seconds per build and 720 seconds per class execution. These are planning estimates, not current measurements. If it reaches the bound, preserve diagnostics and report incomplete; do not trim cases or silently increase/retry until a favorable answer appears.

The driver also supports BAAB with an untimed baseline priming build, inherited from the earlier experiment. Do not launch it merely because ABBA is weak or unfavorable. Any second block must be explicitly selected in advance and all observations retained. This preparation requests only the one ABBA pilot. No automatic speedup threshold or pass/fail optimization verdict is encoded.

## Interpretation

Report all four wall and CPU observations, per-test times, block means and within-block drift. Exact cases, unchanged test source and frozen inputs support equal intended workload. Internal call counts are not instrumented or claimed to have been measured. The old 627-label profile signature does not describe this current uninstrumented workload.

Native formatter microbenchmarks are a separate mechanism check. For the prepared fixed-corpus comparison, export the exact baseline source to a new artifact file and invoke:

```sh
git show 72744baa263ce6d8c8685972d9f7be87d381ee42:macos/core/Sources/RemozioCore/XPCPeerPolicy.swift > .build/xpc-peer-policy-hex-pilot/baseline-xpc.swift
python3 scripts/benchmark-xpc-hex.py \
  --baseline-source .build/xpc-peer-policy-hex-pilot/baseline-xpc.swift \
  --candidate-source macos/core/Sources/RemozioCore/XPCPeerPolicy.swift \
  --baseline-sha256 0175c98e2f253b674fb8d0aade6d8e2cde36c859dd20ef10af38b1268ce50c01 \
  --candidate-sha256 733b03399f655bb225d01215e86066b8444a49abe288e573e531a36c3e491792 \
  --target arm64-apple-macosx26.0 --iterations 20000 --warmup 100 --pairs 6 \
  --output .build/xpc-peer-policy-hex-pilot/hex-microbenchmark
```

Create the parent artifact directory first; every output run directory must be new. This runs a predetermined six alternating AB/BA pairs for each of `-Onone` and `-O`, with 640,000 formatting calls per observation and independent parity before timing. The native workload was fixed before execution using only a portable duration feasibility check; its retained 1,000-iteration Linux measurements are separate evidence. Preserve every sample; no calibration or favorable reruns are part of the invocation. This small formatter comparison is separate from the single four-observation native-class pilot. They must compile the actual frozen helper, use a fixed corpus and equivalent checksums, retain both slower and faster samples, and state the build mode. Formatter-only speed is not native policy construction, Gateway-class or full-CI speed. The class pilot remains sensitive to host load, thermal state, caches and order; a small difference within that variation is inconclusive. This does not alter protected policy validation or make any production Linux claim.
## Cache validation in the same diagnostic workflow

A separate Mac job records the cache identity before running the existing complete
`./scripts/check.sh` with a 120-minute job budget. The native Swift cache smoke
also performs its archive/fresh-checkout roundtrip, known Linux input changes and
changed-source invalidation controls. No normal CI job or required check changes.

After the full check succeeds, `check-native-cache-followup.py` saves only if its
tracked inventory stayed stable through that check. It retains the cold app logs,
simulates fresh-checkout timestamp changes, and appends one fixed comment to the
known Linux storage runner. The compatibility identity must remain unchanged,
the exact content key must change, and restoration must preserve all other input
bytes/modes and their original timestamps. It then reruns repository Python tests,
both real app Debug/Release validations and the protocol Swift tests. It restores
the tracked inputs and cache metadata when finished.

The warm follow-up uses an owned output directory under `RUNNER_TEMP`, outside
compiler cleanup roots. Its logs retain actual compiler phase counts and elapsed
app time for comparison with the cold job. This measures reuse in the same
workspace after timestamp churn; it does not measure an Actions cache download or
a complete warm Mac suite. The workflow uploads all diagnostic results, including
partial or failed runs, and does not automatically retry either pilot.
