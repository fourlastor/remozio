# Signed release dependency experiment

The native reader accepts a signed app containing five declared Sparkle dependencies and ten executable aliases.
The same evidence passes retained generation preflight. The dependencies receive no authority roles.

Run on Apple Silicon with the intended Developer ID Application identity already available:

```sh
python3 scripts/run-release-dependency-experiment.py --identity PUBLIC_SHA1 --team TEAM
```

The options require explicit public identity metadata. The script neither selects an identity implicitly nor exports a private key.
It builds the pinned Sparkle fixture and native inspector. It copies and thins the SDK inside an owned temporary directory.
The fixture builder adds signed schema 2 or 3 declarations; production inspection provides no builder entry point.
Each signed declaration control receives a fresh enclosing signature and passes strict deep verification before inspection.
The unsigned-change control deliberately omits that signature and must fail native validation.
No fixture app, updater, installer or service job starts.

| Case | Observed result |
| --- | --- |
| Five declared SDK dependencies | Accepted; exact hashes and ten aliases verified; generation preflight passed |
| Extra signed executable | Rejected by the complete inventory |
| Wrong trusted Team | Rejected by native signature policy |
| Changed declared hash | Rejected by identity comparison |
| Swapped alias ownership | Rejected by canonical target binding |
| Framework declared as a tool | Rejected by the Mach-O file type check |
| Wrong declared build | Rejected by signed bundle metadata |
| Wrong dependency identifier | Rejected by native signature policy |
| Wrong declared Team | Rejected by identity comparison |
| Signed synthetic feature contract | Schema 3 accepted; retained feature subset passed |
| Missing required feature | Rejected despite matching wire, schema, actions and purposes |
| Unsigned feature change | Rejected by the enclosing native signature |
| Signed legacy contract | No features inferred; retained required feature rejected |

The runner checks each expected rejection stage. An unrelated failure does not count as a passed control.
The owned directory is removed and the original SDK digest remains unchanged.
The [sanitized record](release-dependencies.json) binds the result to the inspected source files.

This experiment proves candidate snapshot inspection. It does not prove notarization, protected installation, quiescence or update activation.
The fixtures omit timestamps. Results on macOS 27 do not prove runtime behavior on macOS 26.
See the [schema and inspection contract](../macos-release-dependencies.md).
