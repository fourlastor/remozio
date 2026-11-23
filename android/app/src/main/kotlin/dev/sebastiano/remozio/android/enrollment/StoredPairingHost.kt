package dev.sebastiano.remozio.android.enrollment

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentSnapshot
import dev.remozio.phone.enrollment.PhoneEnrollment
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.EnrollmentKeyReference
import dev.remozio.phone.enrollment.EnrollmentKeyRole
import dev.remozio.phone.enrollment.RePairProposalMaterial
import dev.remozio.phone.enrollment.RePairReservation
import dev.remozio.phone.enrollment.canAbandonAmbiguousRePair
import dev.remozio.phone.enrollment.rePairPredecessor
import java.util.concurrent.atomic.AtomicBoolean
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.PairingProofPurpose
import dev.remozio.protocol.PairingTranscript
import dev.remozio.protocol.RePairInvitation
import java.security.KeyStore
import kotlinx.coroutines.CancellationException
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
    private val invalidateLocked: suspend (Set<CborValue.Bytes>) -> Unit,
    private val validateKeys: (PhoneEnrollment) -> Unit,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val rePairKeys: RePairKeyCleanup = AndroidRePairKeyCleanup,
    private val onChanged: () -> Unit = {},
) {
    private val liveRePairs = mutableSetOf<CborValue.Bytes>()
    private val preparedLeases = mutableMapOf<CborValue.Bytes, MutableSet<PreparedPairingLease>>()

    /** Explicit setup reads can initialize storage. Ordinary inventory reads keep using openExisting. */
    suspend fun setupSnapshot(): EnrollmentSnapshot = withContext(dispatcher) {
        enrollmentAccess.withLock { openForSetup().use { it.snapshot() } }
    }

    suspend fun inspectRePair(invitation: RePairInvitation): StoredPhoneEnrollment = withContext(dispatcher) {
        enrollmentAccess.withLock {
            checkNotNull(openExisting()).use { store ->
                reconcileRePairLocked(store)
                val snapshot = store.snapshot()
                val previous = rePairPredecessor(snapshot, invitation)
                checkRePairSlot(snapshot, invitation)
                previous
            }
        }
    }

    suspend fun reserveRePair(invitation: RePairInvitation, recordID: ByteArray, epoch: ByteArray,
        keyIDs: List<CborValue.Bytes>): RePairReservation = withContext(dispatcher) {
        enrollmentAccess.withLock {
            checkNotNull(openExisting()).use { store ->
                reconcileRePairLocked(store)
                val snapshot = store.snapshot()
                val previous = rePairPredecessor(snapshot, invitation)
                checkRePairSlot(snapshot, invitation)
                val reservation = RePairReservation(recordID, previous.enrollment.recordID.copyBytes(), epoch, invitation, keyIDs)
                require(EnrollmentKeyRole.entries.none { rePairKeys.contains(reservation.alias(it)) })
                store.reserveRePair(reservation, snapshot.revision)
                liveRePairs.add(reservation.recordID)
                reservation
            }
        }
    }

    private fun checkRePairSlot(snapshot: EnrollmentSnapshot, invitation: RePairInvitation) {
        val mac = invitation.invitation.macID
        if (snapshot.rePairReservations.any { it.macID == mac } ||
            snapshot.entries.any { it.phase == EnrollmentPhase.PREPARED && it.enrollment.macID == mac }) {
            throw RePairAlreadyPending()
        }
    }

    suspend fun prepareRePairProposal(recordID: CborValue.Bytes, material: RePairProposalMaterial) = withContext(dispatcher) {
        enrollmentAccess.withLock {
            require(recordID in liveRePairs)
            checkNotNull(openExisting()).use { store ->
                store.prepareRePairProposal(recordID, material, store.snapshot().revision)
            }
        }
    }

    suspend fun checkpointRePair(recordID: CborValue.Bytes, transcript: PairingTranscript): StoredPhoneEnrollment =
        withContext(dispatcher) {
            enrollmentAccess.withLock {
                require(recordID in liveRePairs)
                checkNotNull(openExisting()).use { store ->
                    store.checkpointRePair(recordID, transcript, store.snapshot().revision)
                        .entries.single { it.enrollment.recordID == recordID }
                }
            }
        }.also { notifyChange() }

    suspend fun markRePairProof(expected: PreparedPairingAccess): PreparedPairingAccess = withContext(dispatcher) {
        enrollmentAccess.withLock {
            val recordID = expected.record.enrollment.recordID
            require(recordID in liveRePairs && expected.lease.isCurrent())
            checkNotNull(openExisting()).use { store ->
                val snapshot = store.snapshot()
                val current = snapshot.entries.single { it.enrollment.recordID == recordID }
                require(current.sameConnectionAs(expected.record))
                val marked = store.markRePairProof(recordID, snapshot.revision)
                    .entries.single { it.enrollment.recordID == recordID }
                PreparedPairingAccess(marked, expected.lease)
            }
        }
    }

    /** Call only after a live setup owner drains, or on startup with no owner for the record. */
    suspend fun finishRePair(recordID: CborValue.Bytes) = withContext(dispatcher) {
        enrollmentAccess.withLock {
            liveRePairs.remove(recordID)
            val leases = preparedLeases[recordID]
            leases?.removeAll { !it.isCurrent() }
            if (leases.isNullOrEmpty()) preparedLeases.remove(recordID)
            reconcileRePairBestEffort { checkNotNull(openExisting()).use { reconcileRePairLocked(it) } }
        }
    }.also { notifyChange() }

    suspend fun reconcileRePairOnStartup() = withContext(dispatcher) {
        enrollmentAccess.withLock {
            reconcileRePairBestEffort { openExisting()?.use { reconcileRePairLocked(it) } }
        }
    }

    private inline fun reconcileRePairBestEffort(cleanup: () -> Unit) {
        try {
            cleanup()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            // Retain the archive evidence so startup or setup can retry incomplete cleanup.
        }
    }

    private fun reconcileRePairLocked(store: EncryptedEnrollmentStore) {
        val initial = store.snapshot()
        val reservations = initial.rePairReservations.filter { it.recordID !in liveRePairs }
        for (reservation in reservations) {
            for (role in EnrollmentKeyRole.entries) {
                rePairKeys.retire(reservation.alias(role), reservation.material?.keys?.get(role.ordinal)?.publicKey)
            }
            store.abandonRePair(reservation.recordID, store.snapshot().revision)
        }
        val unsubmitted = initial.entries.filter {
            it.phase == EnrollmentPhase.PREPARED && it.rePair?.proofMayHaveBeenSent == false &&
                it.enrollment.recordID !in liveRePairs && preparedLeases[it.enrollment.recordID].isNullOrEmpty()
        }
        for (row in unsubmitted) {
            retireUnreferenced(initial, row)
            store.abandonRePair(row.enrollment.recordID, store.snapshot().revision)
        }
        for (row in initial.entries.filter {
            it.phase == EnrollmentPhase.REMOVED && (it.successorRecordID != null || it.rePair != null)
        }) {
            retireUnreferenced(initial, row)
        }
    }

    private fun retireUnreferenced(snapshot: EnrollmentSnapshot, row: StoredPhoneEnrollment) {
        val retained = snapshot.entries.filter { it !== row && it.phase != EnrollmentPhase.REMOVED }
            .flatMap { references(it.enrollment) }.mapTo(mutableSetOf()) { it.alias }
        for (key in references(row.enrollment)) {
            if (key.alias !in retained && rePairKeys.contains(key.alias)) {
                rePairKeys.retire(key.alias, key.publicKey)
            }
        }
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

    suspend fun hasActivatedRePair(recordID: CborValue.Bytes): Boolean = withContext(dispatcher) {
        enrollmentAccess.withLock {
            openExisting()?.use { store -> store.snapshot().entries.any {
                it.enrollment.recordID == recordID && it.phase == EnrollmentPhase.ACTIVE && it.rePair != null
            } } == true
        }
    }

    /** Reconstruct the retained attempt before acquiring its ordinary prepared-record lease. */
    suspend fun recoverable(recordID: CborValue.Bytes): PreparedPairingAccess {
        val transcript = withContext(dispatcher) {
            enrollmentAccess.withLock {
                checkNotNull(openExisting()).use { store ->
                    require(recordID !in liveRePairs)
                    val row = store.snapshot().entries.single { it.enrollment.recordID == recordID }
                    require(row.rePair?.proofMayHaveBeenSent != false)
                    store.recoverPairing(recordID.copyBytes()).transcript
                }
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
                if (row.rePair == null) {
                    invalidatePreparedLocked(affected)
                    invalidateLocked(affected)
                    return@use attempt.activate(store, receipt.copyBytes())
                }
                val previous = store.snapshot()
                val committed = attempt.activate(store, receipt.copyBytes())
                val retired = committed.entries.filter { entry ->
                    entry.phase == EnrollmentPhase.REMOVED && previous.entries.any {
                        it.enrollment.recordID == entry.enrollment.recordID && it.phase != EnrollmentPhase.REMOVED
                    }
                }.map { it.enrollment.recordID }.toSet()
                invalidatePreparedLocked(affected + retired)
                invalidateLocked(affected + retired)
                reconcileRePairBestEffort { reconcileRePairLocked(store) }
                committed
            }
        }
    }.also { notifyChange() }

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

    /** Work admission can be retried from the committed archive after a callback or process failure. */
    private fun notifyChange() { try { onChanged() } catch (_: Exception) { } }

    private fun references(enrollment: PhoneEnrollment): List<EnrollmentKeyReference> =
        listOf(enrollment.transportKey, enrollment.decisionKey, enrollment.biometricKey)

    suspend fun abandonAmbiguousRePair(recordID: CborValue.Bytes, expectedRevision: ULong): EnrollmentSnapshot =
        withContext(dispatcher) {
            enrollmentAccess.withLock {
                checkNotNull(openExisting()).use { store ->
                    val snapshot = store.snapshot()
                    require(snapshot.revision == expectedRevision && recordID !in liveRePairs)
                    require(preparedLeases[recordID].isNullOrEmpty())
                    val row = snapshot.entries.single { it.enrollment.recordID == recordID }
                    require(snapshot.canAbandonAmbiguousRePair(row))
                    invalidateLocked(setOf(recordID))
                    val next = store.abandonAmbiguousRePair(recordID, expectedRevision)
                    val removed = next.entries.single { it.enrollment.recordID == recordID }
                    retireUnreferenced(next, removed)
                    next
                }
            }
        }.also { notifyChange() }

    /** Local removal does not claim that the Mac has revoked the phone. */
    suspend fun remove(recordID: CborValue.Bytes, expectedRevision: ULong): EnrollmentSnapshot = withContext(dispatcher) {
        enrollmentAccess.withLock {
            checkNotNull(openExisting()).use { store ->
                val snapshot = store.snapshot()
                require(snapshot.revision == expectedRevision)
                val row = snapshot.entries.single { it.enrollment.recordID == recordID }
                if (row.phase == EnrollmentPhase.ACTIVE && snapshot.entries.any {
                        it.phase == EnrollmentPhase.PREPARED && it.rePair == null && it.pairing?.replacingRecordID == recordID
                    }) {
                    throw OrdinaryPairingReplacementPending()
                }
                invalidatePreparedLocked(setOf(recordID))
                invalidateLocked(setOf(recordID))
                store.remove(recordID.copyBytes(), expectedRevision)
            }
        }
    }.also { notifyChange() }
}


/** Local liveness only. Removal or activation retires this lease before changing the retained record. */
internal class PreparedPairingLease : AutoCloseable {
    private val active = AtomicBoolean(true)
    fun isCurrent() = active.get()
    override fun close() { active.set(false) }
}
internal class PreparedPairingAccess(val record: StoredPhoneEnrollment, val lease: PreparedPairingLease)

internal class OrdinaryPairingReplacementPending : IllegalStateException("This pairing has a pending replacement")

internal class RePairAlreadyPending : IllegalStateException("This Mac has a pending re-pair attempt")

internal interface RePairKeyCleanup {
    fun contains(alias: String): Boolean
    fun retire(alias: String, expectedPublicKey: CborValue.Bytes?)
}

private object AndroidRePairKeyCleanup : RePairKeyCleanup {
    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun contains(alias: String): Boolean = keyStore().containsAlias(alias)

    override fun retire(alias: String, expectedPublicKey: CborValue.Bytes?) {
        val store = keyStore()
        if (expectedPublicKey == null) {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
        } else {
            val point = store.getCertificate(alias)?.publicKey?.encoded?.takeLast(65)?.toByteArray()
            if (point != null && expectedPublicKey.copyBytes().takeLast(65).toByteArray().contentEquals(point)) {
                store.deleteEntry(alias)
            }
        }
    }
}
