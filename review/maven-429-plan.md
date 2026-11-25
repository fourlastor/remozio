# Maven Central 429s in CI: findings and plan

Workflow read from rock3r/remozio main (FETCH_HEAD, 2026-11-25). Line numbers refer to `.github/workflows/checks.yml` on that commit.

## 1. What each job caches

Five Gradle jobs use the same pattern: `actions/cache/restore` then `actions/cache/save`, with paths `~/.gradle/wrapper/dists` and `~/.gradle/caches/modules-2`.

| Job | Restore | Save | Entry size |
|---|---|---|---|
| linux-protocol (Linux Swift protocol) | L104-113 | L116-125 | 343 MB |
| mac-interop | L422-431 | L434-442 | 426 MB |
| ios | L490-499 | L511-519 | 674 MB |
| kotlin | L542-551 | L554-562 | 373 MB |
| android | L585-594 | L599-607 | 475 MB |

- Key: `gradle-downloads-v1-<job>-<os>-hashFiles(gradle-wrapper.properties, gradle/libs.versions.toml, gradle.properties, **/*.gradle.kts)`. Restore falls back to the prefix `gradle-downloads-v1-<job>-<os>-`.
- So the key already covers the dependency inputs. The repo has no lockfiles and no `verification-metadata.xml`.
- Saves run only on a push to main and only when the exact key missed (L118, L435, L512, L555, L600). Pull requests restore and never save.
- Saves have no `if: always()`. If the Gradle step fails, the save is skipped, so the next main run misses again.
- `setup-java` has no `cache:` input, and the workflow does not use `gradle/actions/setup-gradle`.
- `scripts/ci-build-cache.py` handles only the Mac Swift build caches (`mac-build-v1-*`). It does not touch Gradle.
- `cache-cleanup` (L626-659) runs `scripts/prune-ci-caches.py`. In each family it keeps the newest entry and every key the run saved. It never deleted a Gradle entry in the runs I checked (45468777358, 45487993900, 45500426654, 45504055767). It deletes only the old Mac generation.
- Repositories (settings.gradle.kts): plugins come from google(), gradlePluginPortal(), mavenCentral(). Dependencies come from google(), mavenCentral(). The Plugin Portal redirects to repo.maven.apache.org, which is where the 429 came from.

## 2. Hits and misses (last 10 finished main and PR runs)

Runs: 45516038705, 45514544615, 45512357704, 45505797010, 45504055767, 45500426654, 45490830275, 45489284965, 45487993900 (45520267476 was still running). In these runs, 25 Gradle jobs ran. Every run computed the same key, `...-30da6080...`, because no Gradle input changed.

- 19 hits, 6 misses. All 6 misses were on main pushes. Each miss was a full miss: even the prefix fallback found nothing.
  - 45487993900: ios, kotlin (both then saved).
  - 45500426654: linux-protocol, kotlin (both saved), android (failed with the 429, so not saved).
  - 45504055767: android (saved).
- The PR runs (5 runs, mac-interop only, because of path filtering) always hit.
- Downloads: Gradle does not log each download at the default log level, so a "Download https://repo.maven.apache.org" line count is 0 in every log. Each miss re-fetches the whole entry, which is the wrapper plus modules-2. That is about 2.7 GB over 6 misses (374+674+343+373+475+475 MB), mostly from Maven Central. One job got a 429: the Android build in 45500426654, `Could not GET .../kotlin-gradle-plugins-bom-2.4.21.pom. Received status code 429`. The conscrypt case is older than this window, so I did not check it.
- No hit job showed a Maven Central resolution failure.

## 3. Why downloads still happen

- Not a key change: the key was `30da6080` in every run.
- Not PR read-only: PRs only restore, and they hit.
- Not the prune script: it keeps the newest Gradle entry of each family.
- The cause is GitHub's 10 GB LRU eviction. One generation of caches is about 7.4 GB now (`gh api .../actions/cache/usage`: 7.37 GB, 8 entries). The Mac entries are about 1.9 + 2.4 + 0.3 GB. Each main push saves a new Mac generation of about 4.6 GB before `cache-cleanup` runs at the end. The total passes about 12 GB, and GitHub evicts the least recently used entries. Those are the Gradle entries for kotlin, android, linux-protocol and ios, because PRs rarely restore them. mac-interop's entry is restored by every PR, so it stays recent and survived.
- A failed job does not save, so a 429 on a miss leads to another miss on the next run (android: 45500426654, then 45504055767).
- Gradle offline or verification settings play no part. There is no `--offline` and no verification metadata.

## 4. Options and expected effect

Baseline: about 6 of 25 jobs (24%) start cold. Each cold job makes hundreds of Central requests, and each one is a chance to get a 429.

- **(a) Dependency cache keyed on hashed inputs, saved only on main.** This is already in place (L112 and the others). The problem is that the entries are evicted. The changes that would help:
  1. Make room in the budget. Delete the superseded Mac generation *before* the new one is saved. Or save the Mac entries only when the Mac key changes, and not on every push. Or shrink the Mac entries (the experiments entry alone is 2.4 GB). If the peak stays under 10 GB, Gradle misses go from 6 to about 0 when the inputs are unchanged.
  2. Share one Gradle entry per OS instead of one per job. Replace `${{ github.job }}` with a single `gradle-downloads-v2-<os>-<hash>` that holds the union of the dependencies. This saves about 1.5 GB of duplicates on Linux, and every PR keeps the entry warm. The trade-off is a larger single restore, and the jobs must not race on save (only one job should save).
  3. Save even when the job fails (`if: always() && ...`), so that one 429 does not cause another miss.

  Expected effect: misses fall from 24% to near zero. They come back only when a Gradle input changes, and then the prefix fallback (L113) turns most of a full miss into a partial download.
- **(b) Retry on 429.** Gradle already retries some transient HTTP errors. Further retries can come from `-Dorg.gradle.internal.repository.max.tentatives` and `...initial.backoff` in `gradle.properties` as `systemProp`. These are internal properties and may change between versions. A wrapper retry, which re-runs the Gradle step once on a "status code 429" match, is simpler. Gradle resumes from the partially filled cache, so the second attempt asks for few artifacts. Expected effect: it would have saved the one failure in 45500426654. It costs a few minutes on the rare retry and does not remove the cold downloads. It works well as a cheap safety net next to (a).
- **(c) Mirror or repository order.** Put `google()` first for plugins (it is already first) and add a Central mirror such as the Google Cloud Maven Central mirror (`maven-central.storage-download.googleapis.com/maven2`) before `mavenCentral()`. This spreads requests to hosts that limit GitHub's shared IPs less. The trade-offs: there is one more trust root, and the mirror can lag new releases. A real pull-through proxy (Artifactory, Nexus, or a GitHub Packages proxy) needs hosting and credentials, which is too much for this repo. Expected effect: the number of Central requests on a cold job drops to almost zero, but the bandwidth and time costs of a cold job stay.
- **(d) Dependency locking.** This does not reduce downloads, because the key already hashes the version catalog. It also adds lockfile churn to every bump. It helps reproducibility but does nothing for the 429s. Not recommended for this problem.

## Recommendation

1. Fix the budget overflow, which is the root cause. Prune the old Mac generation before saving the new one, or save Mac entries only when their key changes. Then confirm with `gh api repos/rock3r/remozio/actions/cache/usage` that the peak stays under 10 GB.
2. Merge the five per-job Gradle entries into one entry per OS, with a single saver per OS. This keeps them warm through PR traffic and saves about 1.5 GB.
3. Run the Gradle save step `if: always()` on main.
4. Add a single retry of the Gradle step on a 429 match as a safety net.
5. Consider the Central mirror (c) only if 429s continue after steps 1-4. Skip locking (d).

Verification: over the next 10 main runs, all five Gradle restores should report `Cache restored from key: gradle-downloads-...` unless the hash changes.
