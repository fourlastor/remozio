package dev.sebastiano.remozio.android.requests

import dev.remozio.phone.requests.RequestLimits
import dev.remozio.protocol.CborLimits

/** Capture capacity exceeds the measured 1 MiB argv/environment bound, including CBOR and capture metadata. */
internal fun commandRequestLimits(): RequestLimits = RequestLimits(
    body = CborLimits(2_162_688, 32, 4096),
    capture = CborLimits(2_097_152, 32, 262_144),
    status = CborLimits(65_536, 32, 4096),
    signing = CborLimits(2_228_224, 32, 4096),
)
