package dev.remozio.phone.enrollment

import dev.remozio.protocol.*

class EnrollmentStoreUnavailable : IllegalStateException("Enrollment store unavailable")

/** Exclusive ownership, bounded reads, and durable atomic replacement are required. */
interface EnrollmentStorage : AutoCloseable {
    fun read(maximumBytes: Int): ByteArray?
    fun replace(ciphertext: ByteArray)
}

class EnrollmentSnapshot internal constructor(val revision: ULong, entries: List<StoredPhoneEnrollment>) {
    val entries: List<StoredPhoneEnrollment> = frozenList(entries)
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
        require(state.entries.none { it.enrollment.scope == enrollment.scope && it.phase == EnrollmentPhase.PREPARED })
        commit(state.entries + StoredPhoneEnrollment(enrollment, EnrollmentPhase.PREPARED))
    }

    /** Call after independent Mac authentication and human transcript verification, before sending the biometric proof. */
    fun preparePairing(enrollment: PhoneEnrollment, transcript: PairingTranscript,
        expectedRevision: ULong, minimumEnvelopeVersion: ULong, replacingRecordID: ByteArray? = null): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        require(state.entries.none { it.enrollment.recordID == enrollment.recordID })
        require(state.entries.none { it.enrollment.scope == enrollment.scope && it.phase == EnrollmentPhase.PREPARED })
        val previous = replacingRecordID?.let { target -> state.entries.single { it.enrollment.recordID == id(target) } }
        val active = state.entries.singleOrNull { it.enrollment.scope == enrollment.scope && it.phase == EnrollmentPhase.ACTIVE }
        require(active === previous)
        val row = StoredPhoneEnrollment(enrollment, EnrollmentPhase.PREPARED,
            PreparedPairing(transcript, replacingRecordID, minimumEnvelopeVersion))
        PhonePairingAttempt(transcript, row, previous, minimumEnvelopeVersion)
        commit(state.entries + row)
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
        require(prepared.phase == EnrollmentPhase.PREPARED)
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

    /** Local removal is not Mac-side revocation. The host must close runtime owners and retire unused keys. */
    fun remove(recordID: ByteArray, expectedRevision: ULong): EnrollmentSnapshot = locked {
        checkRevision(expectedRevision)
        val identifier = id(recordID)
        val existing = state.entries.single { it.enrollment.recordID == identifier }
        if (existing.phase == EnrollmentPhase.REMOVED) return@locked state
        commit(state.entries.map { if (it === existing) StoredPhoneEnrollment(it.enrollment, EnrollmentPhase.REMOVED, it.pairing) else it })
    }

    private fun commit(rows: List<StoredPhoneEnrollment>): EnrollmentSnapshot {
        require(state.revision < ULong.MAX_VALUE)
        validate(rows, maximumRecords)
        val candidate = EnrollmentSnapshot(state.revision + 1u, rows)
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
                    val fields = EnrollmentEncoding.fields(DeterministicCbor.decode(plaintext, limits), 2)
                    val schema = EnrollmentEncoding.uint(fields, 0u)
                    require(schema == 1uL || schema == 2uL)
                    val revision = EnrollmentEncoding.uint(fields, 1u)
                    val entries = (fields[2u] as? CborValue.ArrayValue)?.values ?: throw EnrollmentStoreUnavailable()
                    require(entries.size <= maximumRecords)
                    val rows = entries.map { EnrollmentEncoding.decode(it, schema) }
                    validate(rows, maximumRecords)
                    EnrollmentSnapshot(revision, rows)
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
        private fun encode(state: EnrollmentSnapshot, limits: CborLimits) = DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(2u), 1uL to CborValue.Unsigned(state.revision),
            2uL to CborValue.ArrayValue(state.entries.map(EnrollmentEncoding::encode)),
        )), limits)
        private fun validate(rows: List<StoredPhoneEnrollment>, maximumRecords: Int) {
            require(rows.size <= maximumRecords && rows.map { it.enrollment.recordID }.toSet().size == rows.size)
            require(rows.map { it.enrollment.enrollmentTag }.toSet().size == rows.size)
            rows.filter { it.phase != EnrollmentPhase.REMOVED }.groupBy { it.enrollment.scope to it.phase }.values.forEach { require(it.size == 1) }
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
