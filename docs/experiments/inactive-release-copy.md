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
| Compressed signed resource | Real compressed storage reads as the expected data; the copy is uncompressed and signed inspection remains unchanged |
| Valid signed copy | Bytes, link text, manifest and code hashes remain unchanged; copied placement and floors pass |
| Policy advances during preparation | The second policy read rejects the candidate; owned cleanup removes the copy |
| Source descriptor stays writable | A later source mutation cannot change copied bytes or signing evidence |
| Durable signed copy after store reopen | Fresh native signing and placement match; advanced floors and unexpected copied metadata reject recovery |
| Copied file gains a mutation ACL | The whole-tree placement check rejects it; removing the fixture ACL restores the check |

The 71 Core tests also cover cancellation, resource bounds, source replacement, hardlinks, special files and link escape.
They check cleanup against unknown entries and replacement inodes.
They check destination lease retirement and the public Root refusal before source or policy access.

## Limits

Ordinary ownership controls do not establish Root ownership or another account's isolation.
The probe uses an internal ordinary-owner lease and a synthetic policy for the fixture.
Production uses current protected state through the Root-only API.
The raised-floor case changes fixture return values; it changes no real policy.

Data-only copying supports the tested SDK layout and its synthetic compressed resource.
The kernel decodes the resource data before the copier writes a new uncompressed file.
This proves the recorded compressed fixture, not arbitrary resource-fork semantics.
The [copied metadata policy](../macos-copied-release-metadata.md) now rejects flags and unexpected copied attributes.
It does not preserve arbitrary source metadata or replace signature verification.
The [durable component](../macos-durable-release-preparation.md) checks completed-copy reopen.
Root isolation, power loss, unknown-orphan reconciliation, protected service installation, notarization and activation remain pending.
The macOS 26 deployment target does not establish runtime compatibility on macOS 26.

The [evidence record](inactive-release-copy.json) identifies the tested source hashes and host version.
The runner emits control records and a cleanup record as JSON lines.
The evidence record combines successful output with the focused test result and hashes of its listed sources.
Refresh the record only after all controls, cleanup and focused tests pass. The runner does not emit the combined record itself.
The [component guide](../macos-inactive-release-copy.md) describes the production boundary.
