package dev.remozio.android.enrollment

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentSnapshot
import dev.remozio.phone.enrollment.PhoneEnrollment
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.EnrollmentKeyReference
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

    /** Reconstruct the retained attempt before acquiring its ordinary prepared-record lease. */
    suspend fun recoverable(recordID: CborValue.Bytes): PreparedPairingAccess {
        val transcript = withContext(dispatcher) {
            enrollmentAccess.withLock {
                checkNotNull(openExisting()).use { it.recoverPairing(recordID.copyBytes()).transcript }
            }
        }
        return prepared(recordID, transcript)
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
    suspend fun activate(recordID: CborValue.Bytes, receipt: CborValue.Bytes,
        expected: PreparedPairingAccess? = null): EnrollmentSnapshot = withContext(dispatcher) {
        enrollmentAccess.withLock {
            checkNotNull(openExisting()).use { store ->
                val attempt = store.recoverPairing(recordID.copyBytes())
                val row = store.snapshot().entries.single { it.enrollment.recordID == recordID }
                if (expected != null) {
                    require(expected.lease.isCurrent() && expected.record.enrollment.recordID == recordID)
                    require(row.sameConnectionAs(expected.record))
                }
                require(attempt.transcript.verify(receipt.copyBytes(), row.enrollment.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
                validateKeys(row.enrollment)
                val affected = setOfNotNull(recordID, row.pairing?.replacingRecordID)
                invalidatePreparedLocked(affected)
                invalidateLocked(affected)
                attempt.activate(store, receipt.copyBytes())
            }
        }
    }

    /** Only a joined fresh setup owner that never submitted its proof may call this operation. */
    suspend fun abandonUnsubmitted(expected: StoredPhoneEnrollment, retireKeys: () -> Unit) = withContext(dispatcher) {
        require(expected.phase == EnrollmentPhase.PREPARED)
        val pairing = requireNotNull(expected.pairing)
        require(pairing.replacingRecordID == null && expected.enrollment.relayCredential == null)
        enrollmentAccess.withLock {
            checkNotNull(openExisting()).use { store ->
                require(preparedLeases[expected.enrollment.recordID].isNullOrEmpty())
                val snapshot = store.snapshot()
                val current = snapshot.entries.singleOrNull { it.enrollment.recordID == expected.enrollment.recordID }
                if (current != null) {
                    require(current.phase != EnrollmentPhase.ACTIVE)
                    require(current.sameConnectionAs(StoredPhoneEnrollment(expected.enrollment, current.phase, expected.pairing)))
                }
                val keys = references(expected.enrollment)
                require(snapshot.entries.none { row ->
                    row.enrollment.recordID != expected.enrollment.recordID && references(row.enrollment).any { retained ->
                        keys.any { owned -> retained.alias == owned.alias || retained.keyID == owned.keyID || retained.publicKey == owned.publicKey }
                    }
                })
                val ids = setOf(expected.enrollment.recordID)
                invalidatePreparedLocked(ids)
                invalidateLocked(ids)
                if (current?.phase == EnrollmentPhase.PREPARED) store.remove(current.enrollment.recordID.copyBytes(), snapshot.revision)
                // Keep reference checks, durable removal and native retirement under the same enrollment lock.
                retireKeys()
            }
        }
    }

    private fun references(enrollment: PhoneEnrollment): List<EnrollmentKeyReference> =
        listOf(enrollment.transportKey, enrollment.decisionKey, enrollment.biometricKey)

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
