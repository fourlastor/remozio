# Inactive release copy experiment

This experiment uses disposable signed SDK fixtures under an ordinary Mac account.
It prepares copies and inspects metadata. It starts no updater, installer or service.

## Run

Choose the intended Developer ID Application identity and its Team explicitly.
Keep credentials outside the repository.

```sh
python3 scripts/run-release-copy-experiment.py \
  --identity '<Developer ID identity>' --team-id '<Team ID>'
```

The runner builds the guarded probe, clones and signs private SDK fixtures, then removes its temporary directories.
The original SDK must remain unchanged.

## Controls

| Control | Required result |
| --- | --- |
| Valid signed copy | Bytes, link text, manifest and code hashes remain unchanged; copied placement and floors pass |
| Policy advances during preparation | The second policy read rejects the candidate; owned cleanup removes the copy |
| Source descriptor stays writable | A later source mutation cannot change copied bytes or signing evidence |
| Copied file gains a mutation ACL | The whole-tree placement check rejects it; removing the fixture ACL restores the check |

The 45 Core tests also cover cancellation, resource bounds, source replacement, hardlinks, special files and link escape.
They check cleanup against unknown entries and replacement inodes.
They check destination lease retirement and the public Root refusal before source or policy access.

## Limits

Ordinary ownership controls do not establish Root ownership or another account's isolation.
The probe uses an internal ordinary-owner lease and a synthetic policy for the fixture.
Production uses current protected state through the Root-only API.
The raised-floor case changes fixture return values; it changes no real policy.

Data-only copying supports the tested SDK layout.
Arbitrary signed extended attributes and resource forks remain untested.
Crash recovery, protected service installation, notarization and activation remain pending.
The macOS 26 deployment target does not establish runtime compatibility on macOS 26.

The [evidence record](inactive-release-copy.json) identifies the tested source hashes and host version.
The [component guide](../macos-inactive-release-copy.md) describes the production boundary.
