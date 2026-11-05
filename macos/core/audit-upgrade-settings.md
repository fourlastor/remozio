# Setup wait settings

Settings exposes two independent waits for audit maintenance requests.
Each new connection captures the current values.
A running connection keeps the values it started with.

| Setting | Default | Accepted range |
| --- | --- | --- |
| Setup read timeout | 60000 ms | 1–60000 ms |
| Setup result timeout | 60000 ms | 1–300000 ms |

The values are stored in the app's user defaults under
`auditUpgradeReadTimeoutMilliseconds` and `auditUpgradeOperationTimeoutMilliseconds`.
Values must be strings that contain whole decimal milliseconds.
Wrong types, signs, spaces, fractions, overflow and out-of-range values fail before the app opens a service connection.
In that case the panel tells the user to correct Settings. It does not suggest repeated reads.
Reset restores both defaults.

These waits do not change approval expiry or command runtime.
A result timeout does not undo work that the endpoint already performed.
After an unknown result, the user must read saved progress again before another mutation.

## Not included

The waits stay local to this Mac.
Portable setup files do not carry them.
`PortableAppPreferences` does not read these keys.
Sharing the waits through setup files needs a new portable format version. That is separate work.

## Verification limits

`MacAuditUpgradeSettingsTests` covers defaults, sparse values, malformed values, the capture key list
and a fresh capture for each request.
These tests were written but not run as part of this change.
They do not qualify installed services or native administrator approval.
