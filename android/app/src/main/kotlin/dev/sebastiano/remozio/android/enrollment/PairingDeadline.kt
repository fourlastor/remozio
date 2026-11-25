package dev.sebastiano.remozio.android.enrollment

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.PairingTranscript

internal class PairingDeadlineExpired : IllegalStateException()

/** The attempt creates one deadline after it verifies the authenticated transcript. */
internal class PairingDeadline(
    transcript: PairingTranscript,
    private val receivedAt: ElapsedInstant,
    channelRemainingMillis: Long,
    wallAtReceipt: ULong,
) {
    private val transcriptDigest = CborValue.Bytes(transcript.digest())
    private val durationMillis = minOf(
        transcript.expiresAtUnixMillis - transcript.issuedAtUnixMillis,
        channelRemainingMillis.coerceAtLeast(0).toULong(),
    )
    val expiresElapsedMillis: Long
    val clockSkewAdvisory = when {
        wallAtReceipt < transcript.issuedAtUnixMillis -> transcript.issuedAtUnixMillis - wallAtReceipt > 60_000uL
        wallAtReceipt > transcript.expiresAtUnixMillis -> wallAtReceipt - transcript.expiresAtUnixMillis > 60_000uL
        else -> false
    }

    init {
        require(durationMillis <= Long.MAX_VALUE.toULong() &&
            receivedAt.milliseconds <= Long.MAX_VALUE.toULong() - durationMillis)
        expiresElapsedMillis = (receivedAt.milliseconds + durationMillis).toLong()
    }

    fun matches(transcript: PairingTranscript): Boolean = transcriptDigest == CborValue.Bytes(transcript.digest())

    fun isOpen(now: ElapsedInstant): Boolean =
        now.epoch == receivedAt.epoch && now.milliseconds >= receivedAt.milliseconds &&
            now.milliseconds < expiresElapsedMillis.toULong()

    fun requireOpen(now: ElapsedInstant) {
        if (!isOpen(now)) throw PairingDeadlineExpired()
    }
}
