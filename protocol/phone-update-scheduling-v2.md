# Scheduling version 2

The version 2 carrier uses `remozio-update-scheduling/2` and envelope version 2.
Its request and existing response roles retain their version 1 meaning and size bounds.
Kind 6 carries the signed TooLate payload and its 64-byte Root signature.
The outer nonce must match the signed progress nonce.
The carrier has a 9216-byte limit. Its nested TooLate payload keeps its 8192-byte limit.
Unknown fields, kinds, versions and malformed pairs fail decoding.

The request digest uses the canonical version 1 request representation.
The full request, including an apply signature, keeps the same meaning across the carrier boundary.
The phone must verify the Root signature, current enrollment, exact request and original deadline.
A TooLate observation cannot acknowledge consumption or permit an automatic retry.

Version 1 and version 2 messages cannot be substituted.
Version selection requires an explicit authenticated purpose binding.
The phone must not fall back after it sends an application message.

These codecs do not enable an endpoint or advertise support.
Root signing, authenticated routing, release declarations and the phone connection owner remain separate integration work.
Shared vectors use disposable software signatures. They prove no installed Mac-Pixel behavior.
