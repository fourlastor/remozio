package dev.remozio.phone.audit

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlin.test.*

class AuditCacheMigrationTest {
    private val bound = CborLimits(16384, 8, 512)
    private val protocol = AuditPageLimits(bound, bound, bound, 8, bound, bound)
    private val capacity = AuditEvidenceLimits(20, 100000, 20, 10)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private class Disk { var bytes: ByteArray? = null }
    private class Storage(val disk: Disk = Disk()) : AuditCiphertextStorage {
        var writes = 0
        var closed = false
        var failure: IOException? = null
        var commitBeforeFailure = false
        var ignoreWrite = false
        override fun read(maximumBytes: Int): ByteArray? {
            check(!closed)
            return disk.bytes?.copyOf()?.also { require(it.size <= maximumBytes) }
        }
        override fun replace(ciphertext: ByteArray) {
            check(!closed)
            if (failure == null || commitBeforeFailure) {
                writes++
                if (!ignoreWrite) disk.bytes = ciphertext.copyOf()
            }
            failure?.let { throw it }
        }
        override fun close() { closed = true }
    }
    private inner class Fixture {
        private val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val publicKey: ByteArray get() = (keys.public as ECPublicKey).w.let { point ->
            fun scalar(value: java.math.BigInteger) = value.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
            byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        }
        val binding = AuditCacheBinding(id(1), id(2), publicKey)
        val secret = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val cipher = AuditArchiveCipher(secret, bound.maxBytes)
        fun open(storage: Storage, limits: CborLimits = bound) = EncryptedAuditCache.open(storage,
            AuditArchiveCipher(secret, limits.maxBytes), binding, protocol, capacity, limits)
        fun receipt(reason: AuditReason = AuditReason.NONE): ReceivedAuditPage {
            val record = AuditEventMetadata(id(5), id(1), id(2), id(3), 1u, null, null, null,
                AuditEventKind.REQUEST_CREATED, AuditCategory.COMMAND, null, null, AuditAuthentication.SYSTEM,
                AuditOutcome.PENDING, reason, null, null).encode(bound)
            val body = DeterministicCbor.encode(CborValue.Fields(mapOf(
                0uL to CborValue.Unsigned(1u), 1uL to CborValue.Bytes(id(1)), 2uL to CborValue.Bytes(id(2)),
                3uL to CborValue.Bytes(id(3)), 4uL to CborValue.Unsigned(7u), 5uL to CborValue.Unsigned(0u),
                6uL to CborValue.Unsigned(0u), 7uL to CborValue.Unsigned(1u), 8uL to CborValue.Bytes(ByteArray(32)),
                9uL to CborValue.ArrayValue(listOf(CborValue.Bytes(record))),
            )), bound)
            val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(keys.private); update(AuditBatchSigningInput.make(1u, body, bound, bound)); sign()
            })
            return ReceivedAuditPage(AuditBatch.decode(body, bound, bound, 8), body, signature, ElapsedInstant(1, 100u))
        }
    }

    private fun destinationCipher() = AuditArchiveCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), bound.maxBytes)
    private fun Fixture.archive(): ByteArray {
        val storage = Storage()
        open(storage).use { cache -> cache.append(receipt()); cache.append(receipt(AuditReason.UNKNOWN)) }
        return checkNotNull(storage.disk.bytes).copyOf()
    }
    private fun migrate(storage: Storage, cipher: AuditArchiveCipher, binding: AuditCacheBinding,
                        legacy: LegacyAuditArchive?, limits: AuditEvidenceLimits = capacity) =
        AuditCacheMigration.open(storage, cipher, binding, protocol, limits, bound, legacy)

    @Test fun copiesVerifiedProofsAndConflictsUnderTheNewKeyWithoutChangingLegacyBytes() {
        val f = Fixture(); val original = f.archive(); val saved = original.copyOf()
        val legacy = LegacyAuditArchive(original, f.cipher, listOf(f.binding))
        original.fill(0) // The input belongs to the caller. The migration must retain its own copy.
        val storage = Storage(); val destination = destinationCipher()
        migrate(storage, destination, f.binding, legacy).use { cache ->
            assertEquals(2, cache.snapshot().proofs.size)
            assertEquals(setOf(AuditEvidenceConflict.RECORD), cache.snapshot().proofs.last().conflicts)
        }
        assertEquals(1, storage.writes)
        val migrated = checkNotNull(storage.disk.bytes)
        assertFalse(saved.contentEquals(migrated))
        assertContentEquals(f.cipher.decrypt(saved, f.binding), destination.decrypt(migrated, f.binding))
        assertContentEquals(saved, legacy.ciphertext.copyBytes())
    }

    @Test fun recognizesRemovedRootAndStartsAnIndependentCacheForTheNewRoot() {
        val old = Fixture(); val current = Fixture(); val bytes = old.archive()
        val legacy = LegacyAuditArchive(bytes, old.cipher, listOf(current.binding, old.binding, old.binding))
        val storage = Storage(); val destination = destinationCipher()
        migrate(storage, destination, current.binding, legacy).use { cache ->
            assertTrue(cache.snapshot().proofs.isEmpty())
            assertEquals(0, storage.writes)
            cache.append(current.receipt())
        }
        assertEquals(1, storage.writes)
        assertContentEquals(bytes, legacy.ciphertext.copyBytes())
        val oldStorage = Storage(Disk().apply { this.bytes = bytes.copyOf() })
        old.open(oldStorage).use { assertEquals(2, it.snapshot().proofs.size) }
        EncryptedAuditCache.open(Storage(storage.disk), destination, current.binding, protocol, capacity, bound).use {
            assertEquals(1, it.snapshot().proofs.size)
        }
    }

    @Test fun unknownRootOrDamagedCiphertextNeverProducesAnEmptyReplacement() {
        val old = Fixture(); val current = Fixture(); val good = old.archive()
        for (bytes in listOf(good, good.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() })) {
            val storage = Storage(); val legacy = LegacyAuditArchive(bytes, old.cipher, listOf(current.binding))
            assertFailsWith<AuditMigrationUnavailable> { migrate(storage, destinationCipher(), current.binding, legacy) }
            assertNull(storage.disk.bytes); assertEquals(0, storage.writes)
            assertContentEquals(bytes, legacy.ciphertext.copyBytes())
            storage.close()
        }
    }

    @Test fun authenticatedInvalidEvidenceAndCapacityRefusalDoNotFallBackToAnotherRoot() {
        val f = Fixture(); val other = Fixture(); val good = f.archive()
        val plaintext = f.cipher.decrypt(good, f.binding)
        val parsed = (DeterministicCbor.decode(plaintext, bound) as CborValue.Fields).values
        val invalid = f.cipher.encrypt(DeterministicCbor.encode(CborValue.Fields(parsed + (0uL to CborValue.Unsigned(2u))), bound), f.binding)
        val storage = Storage()
        assertFailsWith<AuditCacheException> {
            migrate(storage, destinationCipher(), f.binding, LegacyAuditArchive(invalid, f.cipher, listOf(f.binding, other.binding)))
        }
        assertFails { migrate(storage, destinationCipher(), f.binding,
            LegacyAuditArchive(good, f.cipher, listOf(f.binding)), AuditEvidenceLimits(1, 100000, 20, 10)) }
        assertNull(storage.disk.bytes); assertEquals(0, storage.writes); storage.close()
    }

    @Test fun invalidSignatureNeverMigratesEvenWhenEncryptionAuthenticates() {
        val f = Fixture(); val good = f.archive()
        val parsed = (DeterministicCbor.decode(f.cipher.decrypt(good, f.binding), bound) as CborValue.Fields).values
        val rows = (parsed.getValue(1uL) as CborValue.ArrayValue).values
        val proof = (rows.first() as CborValue.Fields).values
        val malformed = CborValue.Fields(parsed + (1uL to CborValue.ArrayValue(listOf(
            CborValue.Fields(proof + (2uL to CborValue.Bytes(ByteArray(64))))) )))
        val invalid = f.cipher.encrypt(DeterministicCbor.encode(malformed, bound), f.binding)
        val storage = Storage()
        assertFailsWith<AuditEvidenceException> {
            migrate(storage, destinationCipher(), f.binding, LegacyAuditArchive(invalid, f.cipher, listOf(f.binding)))
        }
        assertNull(storage.disk.bytes); assertEquals(0, storage.writes); storage.close()
    }

    @Test fun existingDestinationIgnoresLegacyAndNeverOverwritesIt() {
        val f = Fixture(); val destination = f.cipher
        val storage = Storage(Disk().apply { bytes = f.archive() }); val before = storage.disk.bytes!!.copyOf()
        val unknown = Fixture()
        val legacy = LegacyAuditArchive(unknown.archive(), unknown.cipher, listOf(unknown.binding))
        migrate(storage, destination, f.binding, legacy).use { assertEquals(2, it.snapshot().proofs.size) }
        assertContentEquals(before, storage.disk.bytes); assertEquals(0, storage.writes)
    }

    @Test fun corruptDestinationIsNotRepairedFromGoodLegacy() {
        val f = Fixture(); val storage = Storage(Disk().apply { bytes = byteArrayOf(1, 2, 3) })
        assertFailsWith<AuditCacheException> {
            migrate(storage, f.cipher, f.binding, LegacyAuditArchive(f.archive(), f.cipher, listOf(f.binding)))
        }
        assertContentEquals(byteArrayOf(1, 2, 3), storage.disk.bytes); assertEquals(0, storage.writes); storage.close()
    }

    @Test fun failedOrAmbiguousWritesPreserveLegacyAndReopenOnlyTheCommittedTarget() {
        for (committed in listOf(false, true)) {
            val f = Fixture(); val bytes = f.archive(); val legacy = LegacyAuditArchive(bytes, f.cipher, listOf(f.binding))
            val storage = Storage().apply { failure = IOException("Injected migration failure"); commitBeforeFailure = committed }
            val destination = destinationCipher()
            assertFailsWith<IOException> { migrate(storage, destination, f.binding, legacy) }
            assertContentEquals(bytes, legacy.ciphertext.copyBytes())
            storage.close()
            val reopened = Storage(storage.disk)
            migrate(reopened, destination, f.binding, legacy).use { assertEquals(2, it.snapshot().proofs.size) }
            assertEquals(if (committed) 0 else 1, reopened.writes)
        }
    }

    @Test fun replacementMustBeReadBackBeforeReturningTheCache() {
        val f = Fixture(); val storage = Storage().apply { ignoreWrite = true }
        assertFailsWith<AuditMigrationUnavailable> {
            migrate(storage, destinationCipher(), f.binding, LegacyAuditArchive(f.archive(), f.cipher, listOf(f.binding)))
        }
        assertNull(storage.disk.bytes); assertEquals(1, storage.writes); storage.close()
    }

    @Test fun absentLegacyStartsAnIndependentEmptyCacheWithoutWriting() {
        val f = Fixture(); val storage = Storage()
        migrate(storage, destinationCipher(), f.binding, null).use { assertTrue(it.snapshot().proofs.isEmpty()) }
        assertNull(storage.disk.bytes); assertEquals(0, storage.writes)
    }

    @Test fun scopeAndSizeBoundsRejectBeforeAnyDestinationWrite() {
        val f = Fixture(); val bytes = f.archive(); val storage = Storage()
        val wrongScope = AuditCacheBinding(id(99), id(2), f.publicKey)
        assertFailsWith<IllegalArgumentException> { LegacyAuditArchive(bytes, f.cipher, listOf(f.binding, wrongScope)) }
        assertFailsWith<IllegalArgumentException> { LegacyAuditArchive(bytes, f.cipher, emptyList()) }
        assertFailsWith<IllegalArgumentException> { LegacyAuditArchive(bytes, f.cipher, List(1025) { f.binding }) }
        assertFailsWith<IllegalArgumentException> { LegacyAuditArchive(ByteArray(35), f.cipher, listOf(f.binding)) }
        assertFailsWith<IllegalArgumentException> { LegacyAuditArchive(ByteArray(f.cipher.maximumCiphertextBytes + 1), f.cipher, listOf(f.binding)) }
        assertFailsWith<IllegalArgumentException> {
            migrate(storage, destinationCipher(), wrongScope, LegacyAuditArchive(bytes, f.cipher, listOf(f.binding)))
        }
        assertEquals(0, storage.writes); assertNull(storage.disk.bytes); storage.close()
    }
}
