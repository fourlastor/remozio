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

This prepared slice has not compiled or run tests.
Earlier private component counts do not qualify this source.
The full local gate and rebuilt native peers remain required before publication.
Preview source does not qualify rendered UI states.
Android Keystore, AtomicFile, actual lifecycle and installed Mac-Pixel delivery remain unqualified.
The attended checks require the user at the Mac.
