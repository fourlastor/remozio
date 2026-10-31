# TooLate scheduling responses

A TooLate response reports that the current activation cannot accept a scheduling change.
It binds one exact challenge or apply request.
It does not prove whether an earlier copy of that request committed.
It includes current progress and a digest of the complete canonical request frame.
The apply digest includes its decision signature.
The progress carries no control digest, so it cannot acknowledge consumption.

The Root signature uses `dev.remozio.update-scheduling-too-late`.
The request hash uses `dev.remozio.update-scheduling-request`, one NUL byte and the canonical request frame.
The phone must match its expected channel scope and live request before it accepts the response.
It must retain the original query deadline. It must not retry an uncertain control automatically.

The payload uses a canonical map with four integer keys.
Key 0 is version 1. Key 1 is reason 0 for TooLate.
Key 2 is the 32-byte request digest. Key 3 contains the canonical progress bytes.
Only irreversible progress with no available actions can appear here.
Unknown versions, extra fields, malformed progress and control acknowledgments fail decoding.

These codecs do not enable an endpoint or advertise support.
Root signing, native dispatch, phone reconciliation and release purpose negotiation remain separate integration work.
The shared vectors use disposable software keys. They prove no native service behavior.
