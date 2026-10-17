package dev.remozio.phone.push

import dev.remozio.protocol.*
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The application supplies exclusive ownership, bounded reads and durable atomic replacement outside backups. */
interface PushChallengeStorage {
    fun read(maximumBytes: Int): ByteArray?
    fun replace(ciphertext: ByteArray)
}
class PushChallengeStoreUnavailable : IllegalStateException("Push challenge storage unavailable")

/** Platform code supplies a dedicated hardware key. Software keys are used only by component fixtures. */
class PushChallengeCipher(private val key: SecretKey) {
    private val magic = "RMZPCH01".encodeToByteArray()
    private val aad = "dev.remozio.push.challenge-storage/v1".encodeToByteArray()
    fun encrypt(plaintext: ByteArray): ByteArray {
        require(plaintext.size in 1..MAXIMUM_PLAINTEXT_BYTES)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, key)
        require(cipher.iv.size == 12 && cipher.parameters.getParameterSpec(GCMParameterSpec::class.java).tLen == 128)
        cipher.updateAAD(aad)
        return magic + cipher.iv + cipher.doFinal(plaintext)
    }
    fun decrypt(bytes: ByteArray): ByteArray {
        require(bytes.size in 37..MAXIMUM_CIPHERTEXT_BYTES && bytes.copyOfRange(0, 8).contentEquals(magic))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes.copyOfRange(8, 20))); cipher.updateAAD(aad)
        return cipher.doFinal(bytes, 20, bytes.size - 20)
    }
    override fun toString() = "PushChallengeCipher(redacted)"
    companion object {
        const val MAXIMUM_PLAINTEXT_BYTES = 262_144
        const val MAXIMUM_CIPHERTEXT_BYTES = MAXIMUM_PLAINTEXT_BYTES + 36
    }
}

/** Opaque scheduling identity. Provider challenge bytes never enter a work name or task input. */
class PendingPushChallengeTicket internal constructor(val generation: UUID, tag: ByteArray, candidateID: ByteArray, revision: ByteArray) {
    val tag = CborValue.Bytes(tag)
    val candidateID = CborValue.Bytes(candidateID)
    val revision = CborValue.Bytes(revision)
    override fun toString() = "PendingPushChallengeTicket(redacted)"
}

/**
 * Admit only provider-service deliveries after sender and generation checks. A journal entry authenticates no peer or approval.
 * Trusted configuration selects the generation and boot epoch. A worker must never select its own saved generation.
 * Expiring these buffers never clears the separate durable proof-attempt ledger.
 */
class PendingPushChallenges(
    private val storage: PushChallengeStorage,
    private val cipher: PushChallengeCipher,
    private val maximumEntries: Int,
    private val lifetimeMilliseconds: ULong,
    private val newRevision: () -> ByteArray = { ByteArray(16).also { SecureRandom().nextBytes(it) } },
) {
    private class Entry(val challenge: PushData.TokenChallenge, val revision: CborValue.Bytes, val deadline: ULong)
    private var generation: UUID? = null
    private var epoch: ULong = 0u
    private var last: ULong = 0u
    private var entries = linkedMapOf<CborValue.Bytes, Entry>()
    private var unavailable = false
    private val limits: CborLimits

    init {
        require(maximumEntries in 1..1024 && lifetimeMilliseconds in 1uL..3_600_000uL)
        limits = CborLimits(PushChallengeCipher.MAXIMUM_PLAINTEXT_BYTES, 4, maximumEntries * 8 + 32)
        try {
            storage.read(PushChallengeCipher.MAXIMUM_CIPHERTEXT_BYTES)?.let { bytes ->
                val plain = cipher.decrypt(bytes)
                try {
                    val fields = (DeterministicCbor.decode(plain, limits) as CborValue.Fields).values
                    require(fields.keys == (0uL..5uL).toSet() && fields[0u] == CborValue.Text(DOMAIN) && fields[1u] == CborValue.Unsigned(1u))
                    val id = (fields[2u] as CborValue.Bytes).copyBytes(); require(id.size == 16)
                    val buffer = ByteBuffer.wrap(id); generation = UUID(buffer.long, buffer.long)
                    epoch = (fields[3u] as CborValue.Unsigned).value; last = (fields[4u] as CborValue.Unsigned).value
                    val rows = (fields[5u] as CborValue.ArrayValue).values; require(rows.size <= maximumEntries)
                    for (row in rows) {
                        val values = (row as CborValue.ArrayValue).values; require(values.size == 5)
                        fun value(i: Int) = (values[i] as CborValue.Bytes).copyBytes()
                        val challenge = PushData.TokenChallenge(value(1), value(2), value(0))
                        val revision = value(3); require(revision.size == 16)
                        val deadline = (values[4] as CborValue.Unsigned).value
                        require(deadline > 0uL)
                        require(entries.put(key(challenge), Entry(challenge, CborValue.Bytes(revision), deadline)) == null)
                    }
                    require(encode(checkNotNull(generation), epoch, last, entries).contentEquals(plain))
                } finally { plain.fill(0) }
            }
        } catch (_: Exception) { throw PushChallengeStoreUnavailable() }
    }

    /** A new boot or provider retires buffered deliveries. It does not erase proof claims or any enrollment. */
    @Synchronized fun selectGeneration(selected: UUID, bootEpoch: ULong, nowMilliseconds: ULong) {
        checkAvailable()
        if (generation == selected && epoch == bootEpoch) { clock(bootEpoch, nowMilliseconds); return }
        persist(selected, bootEpoch, nowMilliseconds, linkedMapOf())
    }

    /** Duplicates retain their original deadline. Capacity never evicts an existing delivery. */
    @Synchronized fun admit(selected: UUID, challenge: PushData.TokenChallenge, bootEpoch: ULong,
                            nowMilliseconds: ULong): PendingPushChallengeTicket? {
        checkAvailable(); if (generation != selected) return null
        clock(bootEpoch, nowMilliseconds)
        val current = unexpired(nowMilliseconds); val existing = current[key(challenge)]
        if (existing != null) {
            require(existing.challenge.challenge.contentEquals(challenge.challenge))
            if (current.size != entries.size) persist(selected, epoch, last, current)
            return ticket(selected, existing)
        }
        if (current.size >= maximumEntries) {
            if (current.size != entries.size) persist(selected, epoch, last, current)
            return null
        }
        require(lifetimeMilliseconds <= ULong.MAX_VALUE - nowMilliseconds)
        val revision = newRevision(); require(revision.size == 16)
        val entry = Entry(challenge, CborValue.Bytes(revision), nowMilliseconds + lifetimeMilliseconds)
        require(entries[key(challenge)]?.revision != entry.revision)
        current[key(challenge)] = entry
        persist(selected, epoch, last, current)
        return ticket(selected, entry)
    }

    @Synchronized fun pending(selected: UUID, bootEpoch: ULong, nowMilliseconds: ULong): List<PendingPushChallengeTicket> {
        checkAvailable(); if (generation != selected) return emptyList()
        clock(bootEpoch, nowMilliseconds); prune(selected, nowMilliseconds)
        return entries.values.map { ticket(selected, it) }
    }

    /** Match only metadata received through the authenticated current enrollment channel. Validate scope and token separately. */
    @Synchronized fun match(selected: UUID, metadata: PhonePushRegistrationMetadata, bootEpoch: ULong,
                            nowMilliseconds: ULong): PushData.TokenChallenge? {
        checkAvailable(); if (generation != selected) return null
        clock(bootEpoch, nowMilliseconds); prune(selected, nowMilliseconds)
        return entries[CborValue.Bytes(metadata.enrollmentTag + metadata.candidateID)]?.challenge
    }

    /** An older worker cannot discard a delivery that replaced its ticket. */
    @Synchronized fun discard(ticket: PendingPushChallengeTicket, bootEpoch: ULong, nowMilliseconds: ULong): Boolean {
        checkAvailable(); if (generation != ticket.generation) return false
        clock(bootEpoch, nowMilliseconds)
        val key = CborValue.Bytes(ticket.tag.copyBytes() + ticket.candidateID.copyBytes())
        if (entries[key]?.revision != ticket.revision) return false
        val updated = LinkedHashMap(entries); updated.remove(key); persist(ticket.generation, epoch, last, updated)
        return true
    }
    private fun prune(selected: UUID, now: ULong) {
        val current = unexpired(now)
        if (current.size != entries.size) persist(selected, epoch, last, current)
    }
    private fun unexpired(now: ULong) = LinkedHashMap(entries.filterValues { now < it.deadline })
    private fun clock(bootEpoch: ULong, now: ULong) { require(epoch == bootEpoch && now >= last); last = now }
    private fun persist(selected: UUID, bootEpoch: ULong, now: ULong, updated: LinkedHashMap<CborValue.Bytes, Entry>) {
        val plaintext = encode(selected, bootEpoch, now, updated)
        try { storage.replace(cipher.encrypt(plaintext)) }
        catch (_: Exception) { unavailable = true; throw PushChallengeStoreUnavailable() }
        finally { plaintext.fill(0) }
        generation = selected; epoch = bootEpoch; last = now; entries = updated
    }
    private fun encode(selected: UUID, bootEpoch: ULong, now: ULong, values: LinkedHashMap<CborValue.Bytes, Entry>): ByteArray {
        val id = ByteBuffer.allocate(16).putLong(selected.mostSignificantBits).putLong(selected.leastSignificantBits).array()
        return DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Bytes(id), 3uL to CborValue.Unsigned(bootEpoch), 4uL to CborValue.Unsigned(now),
            5uL to CborValue.ArrayValue(values.values.map { e -> CborValue.ArrayValue(listOf(
                CborValue.Bytes(e.challenge.enrollmentTag), CborValue.Bytes(e.challenge.candidateID), CborValue.Bytes(e.challenge.challenge),
                e.revision, CborValue.Unsigned(e.deadline))) }))), limits)
    }
    private fun key(challenge: PushData.TokenChallenge) = CborValue.Bytes(challenge.enrollmentTag + challenge.candidateID)
    private fun ticket(selected: UUID, entry: Entry) = PendingPushChallengeTicket(selected, entry.challenge.enrollmentTag,
        entry.challenge.candidateID, entry.revision.copyBytes())
    private fun checkAvailable() { if (unavailable) throw PushChallengeStoreUnavailable() }
    override fun toString() = "PendingPushChallenges(redacted)"
    companion object { private const val DOMAIN = "dev.remozio.phone.push.pending-challenges" }
}
