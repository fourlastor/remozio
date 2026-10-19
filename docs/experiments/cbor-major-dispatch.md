# CBOR major-type dispatch measurement

`Reader.read` previously constructed `[0, 2, 3, 4, 5]` and called `contains`
for each supported nonsimple CBOR value. An integer switch accepts exactly the
same major types at the same point, after simple-value handling and before
argument decoding. Unsupported-type error precedence, limits and canonicality
checks remain unchanged.

## Native test comparison, 19 October 2026

Two counterbalanced blocks ran the nine existing
`GatewayRuntimeActivationOperationTests` cases on separate fresh hosted Mac
runners. A is the original array membership check; B is the switch. Builds were
outside timing. Each trial used a fresh, serial XCTest process, the same absolute
source/build paths and flags, and identical opt-in fixture profiling. There was
no stack sampler during these timed trials.

| Block | Position | Variant | Process wall (s) | Process user + system CPU (s) |
| --- | ---: | --- | ---: | ---: |
| ABBA | 1 | A | 493.065 | 488.192 |
| ABBA | 2 | B | 446.571 | 442.139 |
| ABBA | 3 | B | 439.728 | 435.696 |
| ABBA | 4 | A | 422.714 | 419.511 |
| BAAB | 1 | B | 486.415 | 476.808 |
| BAAB | 2 | A | 496.169 | 491.556 |
| BAAB | 3 | A | 458.908 | 454.805 |
| BAAB | 4 | B | 450.304 | 445.778 |

Within each block, the candidate's mean wall time was **3.219%** (14.740 s) and
**1.922%** (9.179 s) shorter; mean process CPU was **3.290%** and **2.512%** lower.
ABBA's adjacent contrasts disagree: B was 9.430% faster in the first pair and
4.025% slower in the second. BAAB's adjacent contrasts both favor B, by 1.966%
and 1.875%, including when B ran before A.

These are modest positive block estimates, not a precise causal saving. Same-
variant timings drifted substantially: the two A observations fell 14.268% in
ABBA and 7.510% in BAAB. Several per-case effects reverse sign. The cause of
variation is unproven, and two runner blocks are not eight independent samples.
No population confidence interval, Release-build benefit, uninstrumented suite
speedup or full-CI saving is established. No further measurement blocks were
selected to seek a favorable result.

All 72 case executions passed without skips. Each trial retained the same 627
profile labels, 51,894 recorded calls, 27 expected thrown calls and zero CPU
measurement errors. Fresh interruption fixtures, assertions, retry ordering,
validation and SQLite durability settings were unchanged. Nested profile spans
overlap; the process CPU column is measured separately with `wait4`.

The harness verified tracked source bytes/types/modes. Retained logs show actual
primary-file decoder compilation in every trial. BAAB also compiled A in an
untimed priming build before its first B. Only decoder bytes differed between
variants. Source restoration was checked for bytes/mode; exact restored mtimes
follow the cleanup implementation rather than a retained post-run snapshot.
Object and bundle hashes were recorded, but their bytes were not archived for
independent verification. Candidate bundle hashes differed between its BAAB
trials despite matching decoder object hashes; the cause was not established.

Environment: arm64 macOS 26.6.2 (25G83), Xcode 26.6 (17F113), Swift 6.3.3,
debug builds targeting `arm64-apple-macosx26.0`, four build jobs. The experiment
used upstream base `204adf4` plus fixture instrumentation. The focused change is
based on `58dbbbe`; the intervening upstream change did not edit these protocol
files. Normal PR checks validate that newer base separately.

## Evidence and narrower synthetic result

- [ABBA run and artifact](https://github.com/fourlastor/remozio/actions/runs/39254240196),
  attempt 1, head `7d9a1edf64d9304c40525e45f95be600e2f521c4`.
  Artifact ZIP SHA-256: `2407232f01a86722cf2c161025146bb654e937e06fe5840668a35bc01569e9b1`.
- [BAAB run and artifact](https://github.com/fourlastor/remozio/actions/runs/39260423522/attempts/2),
  attempt 2, head `26434d82715ce61951f1ea708781a56455974a74`.
  Artifact ZIP SHA-256: `9a10a095fe5c699a3a124b9383d644871a0f81b7b7416257b667f63d5d7d4305`.
  Attempt 1 acquired no runner and executed no steps or measurements; one
  infrastructure retry produced this block.
- [Native harness at the final diagnostic revision](https://github.com/fourlastor/remozio/blob/26434d82715ce61951f1ea708781a56455974a74/scripts/benchmark-core-tests.py).
  Diagnostic workflows, harnesses and fixture profiling remain on the fork.
- [Earlier synthetic decoder run](https://github.com/fourlastor/remozio/actions/runs/39251154997)
  used six balanced pairs per corpus with identical `-Onone -g` compiler settings
  and exact canonical inputs/results/reencoded bytes. Ratios of median wall
  times showed scalar decoding 28.3% shorter and nested decoding 35.0% shorter.
  All 24 observations passed; three scalar candidate observations were
  subsecond (0.921–0.992 s). This supports only synthetic debug decoding, not
  the same percentage improvement in native tests or CI.

Raw logs, profiles, metadata, ZIPs and extracted artifacts were retained locally
with recursive SHA-256 manifests. Independent audits checked source deltas,
workload equivalence, compilation records, artifact hashes and timing summaries.
The two added protocol tests exhaust unsupported major-1/6 headers and simple
major-7 headers, including the existing trailing-byte behavior.
