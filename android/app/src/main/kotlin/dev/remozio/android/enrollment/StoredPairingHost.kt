package dev.remozio.android.enrollment

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentSnapshot
import dev.remozio.phone.enrollment.PhoneEnrollment
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.enrollment.EnrollmentPhase
import java.util.concurrent.atomic.AtomicBoolean
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.PairingProofPurpose
import dev.remozio.protocol.PairingTranscript
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Trusted setup entry point. The caller authenticates the Mac and verifies the human code before preparation. */
internal class StoredPairingHost(
    private val openForSetup: () -> EncryptedEnrollmentStore,
    private val openExisting: () -> EncryptedEnrollmentStore?,
    private val enrollmentAccess: Mutex,
    private val invalidateLocked: (Set<CborValue.Bytes>) -> Unit,
    private val validateKeys: (PhoneEnrollment) -> Unit,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val preparedLeases = mutableMapOf<CborValue.Bytes, MutableSet<PreparedPairingLease>>()

    /** Explicit setup reads can initialize storage. Ordinary inventory reads keep using openExisting. */
    suspend fun setupSnapshot(): EnrollmentSnapshot = withContext(dispatcher) {
        enrollmentAccess.withLock { openForSetup().use { it.snapshot() } }
    }

    /** Only the exact retained PREPARED transcript can authorize a local biometric operation. */
    suspend fun prepared(recordID: CborValue.Bytes, transcript: PairingTranscript): PreparedPairingAccess = withContext(dispatcher) {
        enrollmentAccess.withLock {
            checkNotNull(openExisting()).use { store ->
                val record = store.snapshot().entries.single { it.enrollment.recordID == recordID }
                require(record.phase == EnrollmentPhase.PREPARED)
                require(checkNotNull(record.pairing).transcript.encode().contentEquals(transcript.encode()))
                validateKeys(record.enrollment)
                require(preparedLeases.values.sumOf { it.size } < 32)
                val lease = PreparedPairingLease()
                preparedLeases.getOrPut(recordID) { mutableSetOf() }.add(lease)
                PreparedPairingAccess(record, lease)
            }
        }
    }

    suspend fun release(recordID: CborValue.Bytes, lease: PreparedPairingLease) = withContext(dispatcher) {
        lease.close()
        enrollmentAccess.withLock {
            preparedLeases[recordID]?.let { values ->
                values.remove(lease)
                if (values.isEmpty()) preparedLeases.remove(recordID)
            }
        }
    }

    private fun invalidatePreparedLocked(ids: Set<CborValue.Bytes>) {
        ids.forEach { id -> preparedLeases.remove(id)?.forEach(PreparedPairingLease::close) }
    }

    suspend fun prepare(enrollment: PhoneEnrollment, transcript: PairingTranscript, expectedRevision: ULong,
        minimumEnvelopeVersion: ULong, replacingRecordID: CborValue.Bytes? = null): EnrollmentSnapshot =
        withContext(dispatcher) {
            enrollmentAccess.withLock {
                validateKeys(enrollment)
                openForSetup().use { it.preparePairing(enrollment, transcript, expectedRevision, minimumEnvelopeVersion, replacingRecordID?.copyBytes()) }
            }
        }

    /** Reconstructs the pending attempt from storage; network input cannot supply a replacement transcript. */
    suspend fun activate(recordID: CborValue.Bytes, receipt: CborValue.Bytes): EnrollmentSnapshot = withContext(dispatcher) {
        enrollmentAccess.withLock {
            checkNotNull(openExisting()).use { store ->
                val attempt = store.recoverPairing(recordID.copyBytes())
                val row = store.snapshot().entries.single { it.enrollment.recordID == recordID }
                require(attempt.transcript.verify(receipt.copyBytes(), row.enrollment.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
                validateKeys(row.enrollment)
                val affected = setOfNotNull(recordID, row.pairing?.replacingRecordID)
                invalidatePreparedLocked(affected)
                invalidateLocked(affected)
                attempt.activate(store, receipt.copyBytes())
            }
        }
    }

    /** Local removal does not claim that the Mac has revoked the phone. */
    suspend fun remove(recordID: CborValue.Bytes, expectedRevision: ULong): EnrollmentSnapshot = withContext(dispatcher) {
        enrollmentAccess.withLock {
            checkNotNull(openExisting()).use { store ->
                require(store.snapshot().revision == expectedRevision)
                require(store.snapshot().entries.any { it.enrollment.recordID == recordID })
                invalidatePreparedLocked(setOf(recordID))
                invalidateLocked(setOf(recordID))
                store.remove(recordID.copyBytes(), expectedRevision)
            }
        }
    }
}


/** Local liveness only. Removal or activation retires this lease before changing the retained record. */
internal class PreparedPairingLease : AutoCloseable {
    private val active = AtomicBoolean(true)
    fun isCurrent() = active.get()
    override fun close() { active.set(false) }
}
internal class PreparedPairingAccess(val record: StoredPhoneEnrollment, val lease: PreparedPairingLease)
