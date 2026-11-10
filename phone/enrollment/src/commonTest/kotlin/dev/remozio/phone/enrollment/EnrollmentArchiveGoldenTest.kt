package dev.remozio.phone.enrollment

import dev.remozio.protocol.*
import kotlinx.serialization.json.*
import kotlin.test.*

/** Runs on every target. The vector pins the archive format that Android devices already hold. */
class EnrollmentArchiveGoldenTest {
    private val vector = archiveVector()
    private fun hex(name: String) = vector.hex(name)
    private val maximumRecords = vector.getValue("maximumRecords").jsonPrimitive.int
    private val maximumBytes = vector.getValue("maximumPlaintextBytes").jsonPrimitive.int

    private val cipher = EnrollmentCipher(PlainAead, maximumBytes)
    private val limits = CborLimits(maximumBytes, 8, maximumRecords * 100 + 16)
    private fun open(disk: Disk) = EncryptedEnrollmentStore.open(disk, cipher, maximumRecords)
    private fun disk(plaintext: String) = Disk(cipher.encrypt(hex(plaintext)))

    @Test fun schema2DecodesAndEncodesToTheSameBytes() {
        val snapshot = open(disk("plaintextSchema2")).snapshot()
        assertEquals(vector.getValue("schema2Revision").jsonPrimitive.long.toULong(), snapshot.revision)
        assertEquals(vector.getValue("schema2Phases").jsonArray.map { it.jsonPrimitive.content }, snapshot.entries.map { it.phase.name })
        val encoded = DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Unsigned(2u),
            1uL to CborValue.Unsigned(snapshot.revision),
            2uL to CborValue.ArrayValue(snapshot.entries.map(EnrollmentEncoding::encode)))), limits)
        assertContentEquals(hex("plaintextSchema2"), encoded)
    }

    @Test fun schema1LoadsWithoutPairingAndMigratesOnWrite() {
        val disk = disk("plaintextSchema1")
        val store = open(disk)
        val row = store.snapshot().entries.single()
        assertEquals(vector.getValue("schema1Revision").jsonPrimitive.long.toULong(), store.snapshot().revision)
        assertEquals(EnrollmentPhase.PREPARED, row.phase)
        assertNull(row.pairing)
        store.remove(row.enrollment.recordID.copyBytes(), store.snapshot().revision)
        val written = (DeterministicCbor.decode(cipher.decrypt(disk.bytes!!), limits) as CborValue.Fields).values
        assertEquals(CborValue.Unsigned(2u), written[0u])
    }

    @Test fun recoveredPairingActivatesOnlyWithTheComputerReceipt() {
        val disk = disk("plaintextSchema2")
        val store = open(disk)
        val attempt = store.recoverPairing(hex("preparedRecordId"))
        assertFails { attempt.activate(store, ByteArray(64)) }
        assertEquals(listOf(EnrollmentPhase.ACTIVE, EnrollmentPhase.PREPARED, EnrollmentPhase.REMOVED), store.snapshot().entries.map { it.phase })
        attempt.activate(store, hex("macCommitSignature"))
        store.close()
        assertEquals(listOf(EnrollmentPhase.ACTIVE, EnrollmentPhase.ACTIVE, EnrollmentPhase.REMOVED), open(disk).snapshot().entries.map { it.phase })
    }

    @Test fun envelopeHasTheMagicAndRejectsAnythingElse() {
        val plaintext = hex("plaintextSchema1")
        val sealed = cipher.encrypt(plaintext)
        assertEquals(plaintext.size + 36, sealed.size)
        assertContentEquals("RMZENR01".encodeToByteArray(), sealed.copyOfRange(0, 8))
        assertContentEquals(plaintext, cipher.decrypt(sealed))
        assertFails { cipher.decrypt(sealed.copyOf().also { it[0] = 0 }) }
        assertFails { cipher.decrypt(sealed.copyOfRange(0, 35)) }
        assertFails { cipher.encrypt(ByteArray(maximumBytes + 1)) }
    }

    @Test fun wrongSealedSizeNeverReachesTheArchive() {
        val short = object : EnrollmentAead {
            override fun seal(plaintext: ByteArray, associatedData: ByteArray) = ByteArray(12) + plaintext
            override fun open(sealed: ByteArray, associatedData: ByteArray) = sealed
        }
        assertFails { EnrollmentCipher(short, maximumBytes).encrypt(ByteArray(8)) }
    }

    @Test fun anUnreadableArchiveIsNeverReset() {
        val damaged = disk("plaintextSchema2").also { it.bytes = it.bytes!!.copyOfRange(0, 20) }
        assertFailsWith<EnrollmentStoreUnavailable> { open(damaged) }
        assertEquals(20, damaged.bytes!!.size)
        assertFailsWith<EnrollmentStoreUnavailable> { open(Disk(null)) }
    }
}
