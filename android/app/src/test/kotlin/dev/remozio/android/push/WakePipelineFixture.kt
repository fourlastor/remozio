package dev.remozio.android.push

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.push.*
import dev.remozio.protocol.CborValue
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.KeyGenerator

internal class WakeTestJournal : WakeDemandStorage {
    var bytes: ByteArray? = null
    var failure = false
    var commitThenThrow = false
    var opens = 0
    var closes = 0
    override fun read(maximumBytes: Int) = bytes?.copyOf()
    override fun replace(bytes: ByteArray) {
        if (failure) error("synthetic write failure")
        this.bytes = bytes.copyOf()
        if (commitThenThrow) error("synthetic uncertain write")
    }
    fun open(): WakeDemandStore {
        opens++
        val pending = PendingWakeDemand(this, 1024)
        return object : WakeDemandStore {
            override fun selectGeneration(generation: UUID) = pending.selectGeneration(generation)
            override fun mark(generation: UUID, tag: ByteArray) = pending.mark(generation, tag)
            override fun pending(generation: UUID) = pending.pending(generation)
            override fun complete(ticket: WakeDemandTicket) = pending.complete(ticket)
            override fun close() { closes++ }
        }
    }
}
internal class WakeTestArchive {
    private var bytes: ByteArray? = null
    var unavailable = false
    private val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 262_144)
    fun open(): EncryptedEnrollmentStore {
        check(!unavailable)
        val storage = object : EnrollmentStorage {
            override fun read(maximumBytes: Int) = bytes?.copyOf()
            override fun replace(ciphertext: ByteArray) { bytes = ciphertext.copyOf() }
            override fun close() = Unit
        }
        return if (bytes == null) EncryptedEnrollmentStore.create(storage, cipher, 20)
            else EncryptedEnrollmentStore.open(storage, cipher, 20)
    }
    fun activate(record: PhoneEnrollment) = open().use {
        it.prepare(record, it.snapshot().revision)
        it.activateSyntheticEnrollment(record.recordID.copyBytes(), it.snapshot().revision)
    }
    fun remove(record: PhoneEnrollment) = open().use { it.remove(record.recordID.copyBytes(), it.snapshot().revision) }
    fun active() = open().use { it.snapshot().entries.filter { row -> row.phase == EnrollmentPhase.ACTIVE } }
}
internal fun wakeTestRecord(n: Int): PhoneEnrollment {
    fun id(value: Int) = ByteArray(16) { value.toByte() }
    fun public() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    fun key(role: EnrollmentKeyRole): EnrollmentKeyReference {
        val number = n * 3 + role.ordinal
        return EnrollmentKeyReference(role, id(number), "remozio.${role.aliasPart}.v1.${"%032x".format(number)}",
            public().let { if (role == EnrollmentKeyRole.TRANSPORT) it else it.takeLast(65).toByteArray() })
    }
    return PhoneEnrollment(id(n), id(n), id(100), id(110 + n), id(120 + n), "Synthetic Mac",
        public().takeLast(65).toByteArray(), public(), key(EnrollmentKeyRole.TRANSPORT),
        key(EnrollmentKeyRole.DECISION), key(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { n.toByte() }, null)
}
