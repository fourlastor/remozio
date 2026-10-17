package dev.remozio.android.push

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.PhonePushRegistrationMetadata
import dev.remozio.protocol.PhonePushTokenOffer

internal interface PushProofOwner : AutoCloseable {
    fun retainActiveRecords(recordIDs: Set<CborValue.Bytes>)
    fun claim(record: StoredPhoneEnrollment, metadata: PhonePushRegistrationMetadata, offer: PhonePushTokenOffer): Boolean
}
internal enum class PushProofClaim { CLAIMED, RECOVERY_REQUIRED, OBSOLETE }

/** Enrollment lock precedes the provider and this owner. No method opens a network connection. */
internal class ApplicationPushProofs(private val provider: PushClientOwner, private val open: () -> PushProofOwner) : AutoCloseable {
    private var owner: PushProofOwner? = null
    private var closed = false

    /** Call under enrollmentAccess with a complete, successfully read archive snapshot. */
    fun claim(candidate: PushTokenCandidate, record: StoredPhoneEnrollment, metadata: PhonePushRegistrationMetadata,
              active: List<StoredPhoneEnrollment>): PushProofClaim {
        val current = active.filter { it.phase == EnrollmentPhase.ACTIVE }
        if (record.phase != EnrollmentPhase.ACTIVE || current.none {
                it.enrollment.recordID == record.enrollment.recordID && it.sameConnectionAs(record)
            }) return PushProofClaim.OBSOLETE
        return provider.withCurrentToken(candidate.generation, candidate.revision) {
            access { ledger ->
                ledger.retainActiveRecords(current.map { it.enrollment.recordID }.toSet())
                val offer = PhonePushTokenOffer(candidate.token, candidate.projectID, candidate.senderID, candidate.packageName)
                if (ledger.claim(record, metadata, offer)) PushProofClaim.CLAIMED else PushProofClaim.RECOVERY_REQUIRED
            }
        } ?: PushProofClaim.OBSOLETE
    }

    @Synchronized private fun <T> access(body: (PushProofOwner) -> T): T {
        check(!closed)
        try { return body(owner ?: open().also { owner = it }) }
        catch (failure: Exception) {
            val previous = owner; owner = null
            try { previous?.close() } catch (closing: Exception) { failure.addSuppressed(closing) }
            throw failure
        }
    }
    @Synchronized override fun close() {
        if (!closed) { closed = true; val previous = owner; owner = null; previous?.close() }
    }
}
