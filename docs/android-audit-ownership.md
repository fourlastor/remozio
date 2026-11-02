# Android audit ownership

The application reserves one audit cache for each enrollment incarnation.
The owner verifies every reply before it stores signed evidence.
Network and file work run outside the enrollment mutex.
The same mutex checks current enrollment before it accepts a reply.

Removal and replacement cancel and join the affected owner before the enrollment change commits.
Uncertain cleanup blocks that scope. Other Mac scopes remain independent.
The history reader uses an immutable owned snapshot when a cache is open.
It does not open a second writer or erase unreadable history.

Histories stay separate by Mac, account and authenticated Root key.
Legacy migration copies verified evidence into a separately owned archive.
It preserves the legacy file. An unrecognized Root cannot supply migration authority.

The foreground host owns bounded sync rounds for active enrollments.
Refresh starts a round. Continue resumes a paused round.
Busy clicks do not queue duplicate work. Leaving the foreground joins active streams.
Saved response and completion times use the phone clock.
They do not prove current Mac presence, trust or action authority.

Saved work limits apply to the next explicit round.
Saving limits does not start a sync or delete retained evidence.
The host advertises audit transport only after it verifies actual Root support.

## Qualification

This slice compiled and passed the automated local gate through verified source-bound stage receipts.
The gate covers 40 native stages and 1,265 portable methods.
It also covers 4,300 Core methods with one expected skip and 361 Python methods with 24 expected skips.
Reused results keep their original source and terminal receipts.
Native peers compiled before their interoperability tests.

Five Android instrumentation methods cover Settings, large-font navigation, details dismissal and native accessibility nodes.
The visual record retains 57 inspected component renders.
The current unsigned release APK matches the earlier artifact byte for byte.
The retained renders qualify component appearance, not background work or installed delivery.

Android Keystore, AtomicFile failure behavior and lifecycle behavior on a physical phone remain unqualified.
Installed Root, caller validation, real provider semantics and Mac-Pixel delivery also remain unqualified.
TalkBack traversal and accessibility focus restoration need attended checks.
The attended checks require the user at the Mac.
