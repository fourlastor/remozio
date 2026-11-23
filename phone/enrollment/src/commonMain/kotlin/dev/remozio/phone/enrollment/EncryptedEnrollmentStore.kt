package dev.remozio.phone.enrollment

import dev.remozio.phone.transport.p256SpkiPrefix
import dev.remozio.protocol.*

class EnrollmentStoreUnavailable : IllegalStateException("Enrollment store unavailable")

/** Exclusive ownership, bounded reads, and durable atomic replacement are required. */
interface EnrollmentStorage : AutoCloseable {
    fun read(maximumBytes: Int): ByteArray?
    fun replace(ciphertext: ByteArray)
}

class EnrollmentSnapshot internal constructor(
    val revision: ULong,
    entries: List<StoredPhoneEnrollment>,
    rePairReservations: List<RePairReservation> = emptyList(),
    internal val usesRePairSchema: Boolean = false,
) {
    val entries: List<StoredPhoneEnrollment> = frozenList(entries)
    val rePairReservations: List<RePairReservation> = frozenList(rePairReservations)
    override fun toString() = "EnrollmentSnapshot(redacted)"
}

/** AES-256-GCM with a fresh 12-byte nonce and a 16-byte tag. Sealed output is the nonce, the ciphertext and the tag. */
interface EnrollmentAead {
    fun seal(plaintext: ByteArray, associatedData: ByteArray): ByteArray
    fun open(sealed: ByteArray, associatedData: ByteArray): ByteArray
}

/** Platform code supplies a dedicated hardware key. This envelope is local storage, not a wire message. */
class EnrollmentCipher(private val aead: EnrollmentAead, val maximumPlaintextBytes: Int) {
    init { require(maximumPlaintextBytes in 1..16_777_216) }
    val maximumCiphertextBytes get() = maximumPlaintextBytes + 36
    private val magic = "RMZENR01".encodeToByteArray()
    private val aad = "dev.remozio.phone.enrollments/v1".encodeToByteArray()
    fun encrypt(bytes: ByteArray): ByteArray {
        require(bytes.size <= maximumPlaintextBytes)
        val sealed = aead.seal(bytes, aad)
        require(sealed.size == bytes.size + 28)
        return magic + sealed
    }
    fun decrypt(bytes: ByteArray): ByteArray {
        require(bytes.size in 36..maximumCiphertextBytes && bytes.copyOfRange(0, 8).contentEquals(magic))
        return aead.open(bytes.copyOfRange(8, bytes.size), aad)
    }
}

/**
 * Blocking local ownership transactions. Only trusted setup code may activate or replace an enrollment.
 * A restored archive is not freshness evidence. Current peer trust and key custody must still be checked.
 */
class EncryptedEnrollmentStore private constructor(
    private val storage: EnrollmentStorage,
    private val cipher: EnrollmentCipher,
    private val maximumRecords: Int,
    private var state: EnrollmentSnapshot,
) : AutoCloseable {
    private var unavailable = false
    private var closed = false
    private val limits = limits(cipher, maximumRecords)
    private val lock = newEnrollmentLock()

    private inline fun <T> locked(block: () -> T): T {
        lock.lock()
        try { return block() } finally { lock.unlock() }
    }

    fun snapshot(): EnrollmentSnapshot = locked { checkAvailable(); state }

    /** Prepared material cannot authorize a connection or a decision. It survives an interrupted setup. */
    fun prepare(enrollment: PhoneEnrollment, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        require(state.entries.none { it.enrollment.recordID == enrollment.recordID })
        require(state.entries.none { it.enrollment.scope == enrollment.scope && it.phase == EnrollmentPhase.PREPARED && it.rePair == null })
        commit(state.entries + StoredPhoneEnrollment(enrollment, EnrollmentPhase.PREPARED))
    }

    /** Call after independent Mac authentication and human transcript verification, before sending the biometric proof. */
    fun preparePairing(enrollment: PhoneEnrollment, transcript: PairingTranscript,
        expectedRevision: ULong, minimumEnvelopeVersion: ULong, replacingRecordID: ByteArray? = null): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        require(state.entries.none { it.enrollment.recordID == enrollment.recordID })
        require(state.entries.none { it.enrollment.scope == enrollment.scope && it.phase == EnrollmentPhase.PREPARED && it.rePair == null })
        val previous = replacingRecordID?.let { target -> state.entries.single { it.enrollment.recordID == id(target) } }
        val active = state.entries.singleOrNull { it.enrollment.scope == enrollment.scope && it.phase == EnrollmentPhase.ACTIVE }
        require(active === previous)
        val row = StoredPhoneEnrollment(enrollment, EnrollmentPhase.PREPARED,
            PreparedPairing(transcript, replacingRecordID, minimumEnvelopeVersion))
        PhonePairingAttempt(transcript, row, previous, minimumEnvelopeVersion)
        commit(state.entries + row)
    }

    fun reserveRePair(reservation: RePairReservation, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val previous = rePairPredecessor(state, reservation.invitation)
        require(reservation.predecessorRecordID == previous.enrollment.recordID && reservation.material == null)
        require(state.rePairReservations.none { it.macID == reservation.macID })
        require(state.entries.none { it.phase == EnrollmentPhase.PREPARED && it.enrollment.macID == reservation.macID })
        require(state.entries.none {
            it.enrollment.macID == reservation.macID && it.enrollment.phoneID == previous.enrollment.phoneID &&
                it.enrollment.epoch == reservation.epoch
        })
        commit(state.entries, state.rePairReservations + reservation)
    }

    /** Call before the first proposal write. The prepared proposal owns no active enrollment. */
    fun prepareRePairProposal(recordID: CborValue.Bytes, material: RePairProposalMaterial, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val reservation = state.rePairReservations.single { it.recordID == recordID }
        require(reservation.material == null)
        require(rePairPredecessor(state, reservation.invitation).enrollment.recordID == reservation.predecessorRecordID)
        val newPoints = material.keys.map { CborValue.Bytes(it.pointBytes()) }.toSet()
        require(state.entries.none { row -> row.enrollment.keys.any { CborValue.Bytes(it.pointBytes()) in newPoints } })
        commit(state.entries, state.rePairReservations.map { if (it === reservation) it.withMaterial(material) else it })
    }

    /** Save the exact returned transcript before exposing the comparison or a signer. */
    fun checkpointRePair(recordID: CborValue.Bytes, transcript: PairingTranscript, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val reservation = state.rePairReservations.single { it.recordID == recordID }
        val material = requireNotNull(reservation.material)
        val previous = rePairPredecessor(state, reservation.invitation)
        require(previous.enrollment.recordID == reservation.predecessorRecordID)
        val selected = reservation.invitation.invitation
        val candidate = PhoneEnrollment(recordID.copyBytes(), selected.macID.copyBytes(), selected.accountID.copyBytes(),
            reservation.invitation.predecessor.phoneID.copyBytes(), reservation.epoch.copyBytes(), selected.label,
            selected.authorityPublicKey.copyBytes(), p256SpkiPrefix() + selected.transportPublicKey.copyBytes(), material.keys[0], material.keys[1], material.keys[2], transcript.enrollmentTag.copyBytes(), null)
        val row = StoredPhoneEnrollment(candidate, EnrollmentPhase.PREPARED,
            PreparedPairing(transcript, reservation.predecessorRecordID.copyBytes(), selected.minimumEnvelopeVersion),
            PreparedRePair(reservation.invitation, material.proposal, false))
        PhonePairingAttempt(transcript, row, previous, selected.minimumEnvelopeVersion)
        commit(state.entries + row, state.rePairReservations.filter { it !== reservation })
    }

    /** Persist before submitting a proof. A retained marker is never cleared on transport failure. */
    fun markRePairProof(recordID: CborValue.Bytes, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val row = state.entries.single { it.enrollment.recordID == recordID }
        val setup = requireNotNull(row.rePair)
        require(row.phase == EnrollmentPhase.PREPARED && !setup.proofMayHaveBeenSent)
        require(rePairPredecessor(state, setup.invitation).enrollment.recordID == row.pairing?.replacingRecordID)
        val marked = StoredPhoneEnrollment(row.enrollment, row.phase, row.pairing, PreparedRePair(setup.invitation, setup.proposal, true))
        commit(state.entries.map { if (it === row) marked else it })
    }

    /** The caller drains the live owner and retires its unreferenced keys before dropping the cleanup record. */
    fun abandonRePair(recordID: CborValue.Bytes, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val row = state.entries.singleOrNull { it.enrollment.recordID == recordID }
        if (row != null) {
            require(row.phase == EnrollmentPhase.PREPARED && row.rePair?.proofMayHaveBeenSent == false)
            return@locked commit(state.entries.filter { it !== row })
        }
        require(state.rePairReservations.any { it.recordID == recordID })
        commit(state.entries, state.rePairReservations.filter { it.recordID != recordID })
    }

    /** Explicit local abandonment after an ordinary setup has succeeded in this Mac and account. */
    fun abandonAmbiguousRePair(recordID: CborValue.Bytes, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val row = state.entries.single { it.enrollment.recordID == recordID }
        require(state.canAbandonAmbiguousRePair(row))
        commit(state.entries.map { if (it === row) it.withPhase(EnrollmentPhase.REMOVED) else it })
    }

    /** Restores only the transcript retained in the authenticated local archive. */
    fun recoverPairing(recordID: ByteArray): PhonePairingAttempt = locked {
        checkAvailable()
        val row = state.entries.single { it.enrollment.recordID == id(recordID) }
        val setup = requireNotNull(row.pairing)
        val previous = setup.replacingRecordID?.let { target -> state.entries.single { it.enrollment.recordID == target } }
        PhonePairingAttempt(setup.transcript, row, previous, setup.minimumEnvelopeVersion)
    }

    /** Internal transition used by the receipt-verifying pairing owner. */
    @HiddenFromJava
    internal fun activate(recordID: ByteArray, expectedRevision: ULong, replacingRecordID: ByteArray? = null): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val identifier = id(recordID)
        val prepared = state.entries.single { it.enrollment.recordID == identifier }
        require(prepared.phase == EnrollmentPhase.PREPARED && prepared.rePair == null)
        val active = state.entries.singleOrNull { it.enrollment.scope == prepared.enrollment.scope && it.phase == EnrollmentPhase.ACTIVE }
        require(active?.enrollment?.recordID == replacingRecordID?.let(::id))
        commit(state.entries.map {
            when {
                it === prepared -> StoredPhoneEnrollment(it.enrollment, EnrollmentPhase.ACTIVE, it.pairing)
                it === active -> StoredPhoneEnrollment(it.enrollment, EnrollmentPhase.REMOVED, it.pairing)
                else -> it
            }
        })
    }

    @HiddenFromJava
    internal fun activateRePair(recordID: CborValue.Bytes, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val candidate = state.entries.single { it.enrollment.recordID == recordID }
        val rePair = requireNotNull(candidate.rePair)
        require(rePair.proofMayHaveBeenSent)
        if (candidate.phase == EnrollmentPhase.ACTIVE) {
            val previous = state.entries.single { it.enrollment.recordID == candidate.pairing?.replacingRecordID }
            require(previous.successorRecordID == recordID)
            return@locked state
        }
        require(candidate.phase == EnrollmentPhase.PREPARED)
        val previous = rePairPredecessor(state, rePair.invitation)
        val proof = requireNotNull(candidate.pairing)
        require(previous.enrollment.recordID == proof.replacingRecordID)
        val siblingEntries = state.entries.filter { row ->
            if (row === candidate || row.phase != EnrollmentPhase.PREPARED ||
                row.pairing?.replacingRecordID != previous.enrollment.recordID) return@filter false
            val sibling = row.rePair ?: return@filter false
            if (!sibling.proofMayHaveBeenSent) return@filter true
            val transcript = requireNotNull(row.pairing).transcript
            transcript.expectedTrustRevision == proof.transcript.expectedTrustRevision &&
                transcript.setupID != proof.transcript.setupID && row.enrollment.epoch != candidate.enrollment.epoch &&
                row.enrollment.keys.none { key -> candidate.enrollment.keys.any {
                    it.keyID == key.keyID || it.alias == key.alias || it.pointBytes().contentEquals(key.pointBytes())
                } }
        }.toSet()
        commit(state.entries.map {
            when {
                it === candidate -> it.withPhase(EnrollmentPhase.ACTIVE)
                it === previous -> it.withPhase(EnrollmentPhase.REMOVED, recordID)
                it in siblingEntries -> it.withPhase(EnrollmentPhase.REMOVED)
                else -> it
            }
        })
    }

    /** Local removal is not Mac-side revocation. The host must close runtime owners and retire unused keys. */
    fun remove(recordID: ByteArray, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val identifier = id(recordID)
        val existing = state.entries.single { it.enrollment.recordID == identifier }
        if (existing.phase == EnrollmentPhase.REMOVED) return@locked state
        require(existing.phase != EnrollmentPhase.PREPARED || existing.rePair == null)
        commit(state.entries.map { if (it === existing) it.withPhase(EnrollmentPhase.REMOVED) else it })
    }

    private fun commit(
        rows: List<StoredPhoneEnrollment>,
        reservations: List<RePairReservation> = state.rePairReservations,
    ): EnrollmentSnapshot {
        require(state.revision < ULong.MAX_VALUE)
        validate(rows, reservations, maximumRecords)
        val usesRePairSchema = state.usesRePairSchema || reservations.isNotEmpty() ||
            rows.any { it.rePair != null || it.successorRecordID != null }
        val candidate = EnrollmentSnapshot(state.revision + 1u, rows, reservations, usesRePairSchema)
        val plaintext = encode(candidate, limits)
        val encrypted = try { cipher.encrypt(plaintext) } finally { plaintext.fill(0) }
        try { storage.replace(encrypted) }
        catch (_: Exception) { unavailable = true; throw EnrollmentStoreUnavailable() }
        state = candidate
        return candidate
    }
    private fun checkAvailable() { if (closed || unavailable) throw EnrollmentStoreUnavailable() }
    private fun checkRevision(revision: ULong) { checkAvailable(); require(state.revision == revision) }
    override fun close() { locked { if (!closed) { closed = true; storage.close() } } }

    companion object {
        /** Caller retains storage on failure. Creation never resets an existing archive. */
        fun create(storage: EnrollmentStorage, cipher: EnrollmentCipher, maximumRecords: Int): EncryptedEnrollmentStore {
            val limits = limits(cipher, maximumRecords)
            try {
                require(storage.read(cipher.maximumCiphertextBytes) == null)
                val initial = EnrollmentSnapshot(0u, emptyList())
                val plaintext = encode(initial, limits)
                try { storage.replace(cipher.encrypt(plaintext)) } finally { plaintext.fill(0) }
                return EncryptedEnrollmentStore(storage, cipher, maximumRecords, initial)
            } catch (_: Exception) { throw EnrollmentStoreUnavailable() }
        }
        /** Missing, invalid, or incompatible state fails without creating a replacement. */
        fun open(storage: EnrollmentStorage, cipher: EnrollmentCipher, maximumRecords: Int): EncryptedEnrollmentStore {
            val limits = limits(cipher, maximumRecords)
            try {
                val encrypted = storage.read(cipher.maximumCiphertextBytes) ?: throw EnrollmentStoreUnavailable()
                val plaintext = cipher.decrypt(encrypted)
                val restored = try {
                    val decoded = DeterministicCbor.decode(plaintext, limits)
                    val schema = EnrollmentEncoding.uint((decoded as CborValue.Fields).values, 0u)
                    require(schema in 1uL..3uL)
                    val fields = EnrollmentEncoding.fields(decoded, if (schema == 3uL) 3 else 2)
                    val revision = EnrollmentEncoding.uint(fields, 1u)
                    val entries = (fields[2u] as? CborValue.ArrayValue)?.values ?: throw EnrollmentStoreUnavailable()
                    require(entries.size <= maximumRecords)
                    val rows = entries.map { EnrollmentEncoding.decode(it, schema) }
                    val reservations = if (schema != 3uL) emptyList() else
                        (fields.getValue(3u) as CborValue.ArrayValue).values.map(EnrollmentEncoding::decodeReservation)
                    validate(rows, reservations, maximumRecords)
                    EnrollmentSnapshot(revision, rows, reservations, schema == 3uL)
                } finally { plaintext.fill(0) }
                return EncryptedEnrollmentStore(storage, cipher, maximumRecords, restored)
            } catch (_: Exception) { throw EnrollmentStoreUnavailable() }
        }
        /** Run before provisioning any persistent key or file. The empty archive must fit. */
        fun validateConfiguration(maximumRecords: Int, maximumPlaintextBytes: Int) {
            require(maximumRecords in 1..1024 && maximumPlaintextBytes in 1..16_777_216)
            encode(EnrollmentSnapshot(0u, emptyList()), CborLimits(maximumPlaintextBytes, 8, maximumRecords * 100 + 16))
        }
        private fun limits(cipher: EnrollmentCipher, records: Int): CborLimits {
            validateConfiguration(records, cipher.maximumPlaintextBytes)
            return CborLimits(cipher.maximumPlaintextBytes, 8, records * 100 + 16)
        }
        private fun encode(state: EnrollmentSnapshot, limits: CborLimits): ByteArray {
            val extended = state.usesRePairSchema
            val schema = if (extended) 3uL else 2uL
            val fields = mutableMapOf<ULong, CborValue>(
                0uL to CborValue.Unsigned(schema), 1uL to CborValue.Unsigned(state.revision),
                2uL to CborValue.ArrayValue(state.entries.map { EnrollmentEncoding.encode(it, schema) }),
            )
            if (extended) fields[3u] = CborValue.ArrayValue(state.rePairReservations.map(EnrollmentEncoding::encodeReservation))
            return DeterministicCbor.encode(CborValue.Fields(fields), limits)
        }

        private fun validate(rows: List<StoredPhoneEnrollment>, reservations: List<RePairReservation>, maximumRecords: Int) {
            val rowIDs = rows.associateBy { it.enrollment.recordID }
            require(rows.size + reservations.size <= maximumRecords && rowIDs.size == rows.size)
            require(rows.map { it.enrollment.enrollmentTag }.toSet().size == rows.size)
            rows.filter { it.phase == EnrollmentPhase.ACTIVE || (it.phase == EnrollmentPhase.PREPARED && it.rePair == null) }
                .groupBy { it.enrollment.scope to it.phase }.values.forEach { require(it.size == 1) }
            require(reservations.map { it.macID }.toSet().size == reservations.size)
            require(reservations.map { it.recordID }.toSet().size == reservations.size)
            val reservedIDs = reservations.flatMap { it.keyIDs }
            require(reservedIDs.toSet().size == reservedIDs.size)
            val existingKeys = rows.flatMap { it.enrollment.keys }
            val existingIDs = existingKeys.map { it.keyID }.toSet()
            val existingAliases = existingKeys.map { it.alias }.toSet()
            val existingPoints = existingKeys.map { CborValue.Bytes(it.pointBytes()) }.toSet()
            require(reservedIDs.none { it in existingIDs })
            for (reservation in reservations) {
                require(reservation.recordID !in rowIDs && reservation.predecessorRecordID in rowIDs)
                require(EnrollmentKeyRole.entries.none { reservation.alias(it) in existingAliases })
                require(reservation.material?.keys.orEmpty().none { CborValue.Bytes(it.pointBytes()) in existingPoints })
            }
            for (row in rows) {
                row.successorRecordID?.let { id ->
                    val successor = requireNotNull(rowIDs[id])
                    require(successor.phase != EnrollmentPhase.PREPARED && successor.rePair?.proofMayHaveBeenSent == true)
                    require(successor.pairing?.replacingRecordID == row.enrollment.recordID)
                    require(successor.enrollment.scope == row.enrollment.scope && successor.enrollment.phoneID == row.enrollment.phoneID)
                }
                if (row.rePair != null) require(row.pairing?.replacingRecordID in rowIDs)
            }
            val aliases = mutableMapOf<String, Pair<Pair<CborValue.Bytes, CborValue.Bytes>, EnrollmentKeyReference>>()
            val keyIDs = mutableMapOf<CborValue.Bytes, String>()
            val materials = mutableMapOf<CborValue.Bytes, Pair<Pair<CborValue.Bytes, CborValue.Bytes>, EnrollmentKeyRole>>()
            for (row in rows) for (key in row.enrollment.keys) {
                val prior = aliases.firstWriter(key.alias, row.enrollment.scope to key)
                require(prior == null || (prior.first == row.enrollment.scope && prior.second.role == key.role && prior.second.keyID == key.keyID && prior.second.publicKey == key.publicKey))
                val priorID = keyIDs.firstWriter(key.keyID, key.alias)
                require(priorID == null || priorID == key.alias)
                val owner = row.enrollment.scope to key.role
                val priorMaterial = materials.firstWriter(CborValue.Bytes(key.pointBytes()), owner)
                require(priorMaterial == null || priorMaterial == owner)
            }
        }
        private fun <K, V : Any> MutableMap<K, V>.firstWriter(key: K, value: V): V? = this[key].also { if (it == null) this[key] = value }
    }
}
