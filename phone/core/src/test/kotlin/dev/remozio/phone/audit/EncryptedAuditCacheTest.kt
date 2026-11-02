package dev.remozio.phone.audit

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlin.test.*

class EncryptedAuditCacheTest {
    private val bound = CborLimits(16384, 8, 512)
    private val protocol = AuditPageLimits(bound, bound, bound, 8, bound, bound)
    private val capacity = AuditEvidenceLimits(20, 100000, 20, 10)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private class Disk { var bytes: ByteArray? = null }
    private class Storage(val disk: Disk) : AuditCiphertextStorage {
        var fail = false
        var failure: Throwable = IOException("Injected write failure")
        var commitBeforeFailure = false
        var writes = 0
        var closed = false
        override fun read(maximumBytes: Int): ByteArray? {
            check(!closed)
            return disk.bytes?.also { check(it.size <= maximumBytes) }?.copyOf()
        }
        override fun replace(ciphertext: ByteArray) {
            check(!closed)
            if (!fail || commitBeforeFailure) { disk.bytes = ciphertext.copyOf(); writes++ }
            if (fail) throw failure
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
        fun open(storage: Storage, limits: CborLimits = bound, localStorage: Storage? = null, clock: () -> Long = { 12345 }) =
            EncryptedAuditCache.open(storage, AuditArchiveCipher(secret, limits.maxBytes), binding, protocol, capacity, limits,
                localSync = { verified -> localStorage?.let { AuditLocalSyncArchive.open(it, secret, binding, verified, clock) } })
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

    @Test fun encryptionIsRandomizedAndBoundToEveryEnrollmentField() {
        val f = Fixture(); val plaintext = "synthetic audit archive".encodeToByteArray()
        val one = f.cipher.encrypt(plaintext, f.binding); val two = f.cipher.encrypt(plaintext, f.binding)
        assertFalse(one.contentEquals(two))
        assertContentEquals(plaintext, f.cipher.decrypt(one, f.binding))
        for (binding in listOf(AuditCacheBinding(id(9), id(2), f.publicKey), AuditCacheBinding(id(1), id(9), f.publicKey),
            AuditCacheBinding(id(1), id(2), Fixture().publicKey))) {
            assertFailsWith<GeneralSecurityException> { f.cipher.decrypt(one, binding) }
        }
        f.binding.macID.fill(0); f.binding.accountID.fill(0); f.binding.authorityPublicKey.fill(0)
        assertContentEquals(plaintext, f.cipher.decrypt(one, f.binding))
        for (index in listOf(0, 7, 8, 19, 20, one.lastIndex)) {
            val altered = one.copyOf().apply { this[index] = (this[index].toInt() xor 1).toByte() }
            assertFails { f.cipher.decrypt(altered, f.binding) }
        }
        assertFailsWith<GeneralSecurityException> { Fixture().cipher.decrypt(one, f.binding) }
        assertFailsWith<AuditCacheException> { f.cipher.decrypt(ByteArray(35), f.binding) }
        assertFailsWith<AuditCacheException> { f.cipher.encrypt(ByteArray(bound.maxBytes + 1), f.binding) }
        assertFailsWith<AuditCacheException> { f.cipher.decrypt(ByteArray(f.cipher.maximumCiphertextBytes + 1), f.binding) }
    }

    @Test fun persistsAndRestoresConflictingEvidenceWithoutPlaintextWrites() {
        val f = Fixture(); val disk = Disk(); val storage = Storage(disk); val cache = f.open(storage)
        val first = f.receipt()
        assertEquals(AuditEvidenceAcceptance.ADDED, cache.append(first))
        assertEquals(AuditEvidenceAcceptance.DUPLICATE, cache.append(first))
        assertEquals(1, storage.writes)
        assertEquals(AuditEvidenceAcceptance.CONFLICT, cache.append(f.receipt(AuditReason.UNKNOWN)))
        val encrypted = checkNotNull(disk.bytes)
        assertFalse(encrypted.contentEquals(first.canonicalBody))
        val plaintext = f.cipher.decrypt(encrypted, f.binding)
        assertFalse(encrypted.contentEquals(plaintext))
        cache.close(); cache.close(); assertTrue(storage.closed)
        assertFailsWith<IllegalStateException> { cache.snapshot() }
        f.open(Storage(disk)).use { restored ->
            val snapshot = restored.snapshot()
            assertEquals(2, snapshot.proofs.size)
            assertEquals(setOf(AuditEvidenceConflict.RECORD), snapshot.proofs.last().conflicts)
            assertEquals(AuditReason.NONE, snapshot.epochs.single().records.single().reason)
        }
    }

    @Test fun failedWritesNeverPublishCandidateAndRequireReopening() {
        for (committed in listOf(false, true)) {
            val f = Fixture(); val disk = Disk(); val storage = Storage(disk); val cache = f.open(storage)
            cache.append(f.receipt()); val oldBytes = checkNotNull(disk.bytes).copyOf()
            storage.fail = true; storage.commitBeforeFailure = committed
            assertFailsWith<IOException> { cache.append(f.receipt(AuditReason.UNKNOWN)) }
            assertEquals(1, cache.snapshot().proofs.size)
            assertFailsWith<IllegalStateException> { cache.append(f.receipt(AuditReason.UNKNOWN)) }
            if (!committed) assertContentEquals(oldBytes, disk.bytes)
            cache.close()
            f.open(Storage(disk)).use { assertEquals(if (committed) 2 else 1, it.snapshot().proofs.size) }
        }
    }

    @Test fun unexpectedStorageFailureAlsoBlocksFurtherWrites() {
        val f = Fixture(); val storage = Storage(Disk()); val cache = f.open(storage)
        cache.append(f.receipt())
        storage.fail = true; storage.failure = AssertionError("Injected storage error")
        assertFailsWith<AssertionError> { cache.append(f.receipt(AuditReason.UNKNOWN)) }
        assertEquals(1, cache.snapshot().proofs.size)
        assertFailsWith<IllegalStateException> { cache.append(f.receipt(AuditReason.UNKNOWN)) }
        cache.close()
    }

    @Test fun corruptCiphertextAndInvalidAuthenticatedArchivesNeverResetTheFile() {
        val f = Fixture(); val disk = Disk()
        f.open(Storage(disk)).use { it.append(f.receipt()) }
        val good = checkNotNull(disk.bytes).copyOf()
        disk.bytes = good.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        val damaged = checkNotNull(disk.bytes).copyOf(); val storage = Storage(disk)
        assertFailsWith<GeneralSecurityException> { f.open(storage) }; storage.close()
        assertContentEquals(damaged, disk.bytes)
        val parsed = (DeterministicCbor.decode(f.cipher.decrypt(good, f.binding), bound) as CborValue.Fields).values
        val rows = (parsed.getValue(1uL) as CborValue.ArrayValue).values
        val proof = (rows.single() as CborValue.Fields).values
        val invalid = listOf(
            CborValue.Fields(parsed + (0uL to CborValue.Unsigned(2u))),
            CborValue.Fields(parsed + (2uL to CborValue.Null)),
            CborValue.Fields(parsed + (1uL to CborValue.ArrayValue(rows + rows))),
            CborValue.Fields(parsed + (1uL to CborValue.ArrayValue(listOf(CborValue.Fields(proof + (0uL to CborValue.Unsigned(9u))))))),
            CborValue.Fields(parsed + (1uL to CborValue.ArrayValue(listOf(CborValue.Fields(proof + (2uL to CborValue.Bytes(ByteArray(64)))))))),
        )
        for (value in invalid) {
            disk.bytes = f.cipher.encrypt(DeterministicCbor.encode(value, bound), f.binding)
            val saved = checkNotNull(disk.bytes).copyOf(); val owner = Storage(disk)
            assertFails { f.open(owner) }; owner.close()
            assertContentEquals(saved, disk.bytes)
        }
    }

    @Test fun archiveCapacityFailureLeavesMemoryAndStorageUnchanged() {
        val f = Fixture(); val disk = Disk(); val storage = Storage(disk)
        f.open(storage, CborLimits(32, 8, 512)).use { cache ->
            assertFailsWith<CborException> { cache.append(f.receipt()) }
            assertTrue(cache.snapshot().proofs.isEmpty())
            assertNull(disk.bytes); assertEquals(0, storage.writes)
        }
    }

    @Test fun localMetadataIsEncryptedBoundAndSeparatedFromProofCiphertextEvenWithTheSameKey() {
        val f = Fixture(); val cipher = AuditArchiveCipher.localSync(f.secret)
        val plain = "disposable local sync metadata".encodeToByteArray()
        val one = cipher.encrypt(plain, f.binding); val two = cipher.encrypt(plain, f.binding)
        assertFalse(one.contentEquals(two)); assertContentEquals(plain, cipher.decrypt(one, f.binding))
        for (binding in listOf(AuditCacheBinding(id(9), id(2), f.publicKey), AuditCacheBinding(id(1), id(9), f.publicKey),
            AuditCacheBinding(id(1), id(2), Fixture().publicKey))) {
            assertFailsWith<GeneralSecurityException> { cipher.decrypt(one, binding) }
        }
        assertFailsWith<GeneralSecurityException> { AuditArchiveCipher.localSync(Fixture().secret).decrypt(one, f.binding) }
        assertFailsWith<GeneralSecurityException> { f.cipher.decrypt(one.copyOf().also {
            "RMZAUD01".encodeToByteArray().copyInto(it)
        }, f.binding) }
        val proofCiphertext = f.cipher.encrypt(plain, f.binding)
        assertFailsWith<GeneralSecurityException> { cipher.decrypt(proofCiphertext.copyOf().also {
            "RMZAS001".encodeToByteArray().copyInto(it)
        }, f.binding) }
        assertFails { cipher.encrypt(ByteArray(1025), f.binding) }
        assertFails { cipher.decrypt(ByteArray(1061), f.binding) }
    }

    @Test fun localMetadataRequiresRetainedProofsAndDamagedMetadataNeverRewritesTheEvidenceArchive() {
        val f = Fixture(); val disk = Disk(); val local = Disk(); val receipt = f.receipt()
        f.open(Storage(disk), localStorage = Storage(local)).use { cache ->
            cache.append(receipt)
            assertNull(cache.localSyncTimes()) // An offline import must not become a fresh receipt.
            cache.recordLocalSync(AuditEvidenceKind.PAGE, receipt.canonicalBody, completed = true)
            assertEquals(12345L, assertNotNull(cache.localSyncTimes()).lastCompleted?.unixMilliseconds)
        }
        val proofArchive = checkNotNull(disk.bytes).copyOf(); val localArchive = checkNotNull(local.bytes).copyOf()
        local.bytes = localArchive.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        val damaged = local.bytes?.copyOf(); val localOwner = Storage(local)
        f.open(Storage(disk), localStorage = localOwner).use { cache ->
            assertEquals(1, cache.snapshot().proofs.size); assertNull(cache.localSyncTimes())
        }
        assertEquals(0, localOwner.writes); assertContentEquals(damaged, local.bytes); assertContentEquals(proofArchive, disk.bytes)
        local.bytes = localArchive
        f.open(Storage(Disk()), localStorage = Storage(local)).use { cache ->
            assertTrue(cache.snapshot().proofs.isEmpty()); assertNull(cache.localSyncTimes())
        }
        assertContentEquals(localArchive, local.bytes)
    }

    @Test fun unknownOrMalformedLocalMetadataCannotHideValidHistoryOrRunThePhoneClockOnLoad() {
        val f = Fixture(); val disk = Disk(); val local = Disk(); val receipt = f.receipt()
        f.open(Storage(disk)).use { it.append(receipt) }
        val savedProofs = checkNotNull(disk.bytes).copyOf()
        val badValues = listOf(
            CborValue.Fields(mapOf(0uL to CborValue.Unsigned(2u), 1uL to CborValue.Null, 2uL to CborValue.Null)),
            CborValue.Fields(mapOf(0uL to CborValue.Unsigned(1u), 1uL to CborValue.Null, 2uL to CborValue.Null)),
            CborValue.Fields(mapOf(0uL to CborValue.Unsigned(1u), 1uL to CborValue.ArrayValue(listOf(
                CborValue.Unsigned(ULong.MAX_VALUE), CborValue.Bytes(ByteArray(32)))), 2uL to CborValue.Null)),
            CborValue.Fields(mapOf(0uL to CborValue.Unsigned(1u), 1uL to CborValue.ArrayValue(listOf(
                CborValue.Unsigned(123u), CborValue.Bytes(ByteArray(31)))), 2uL to CborValue.Null)),
        )
        for (bad in badValues) {
            local.bytes = AuditArchiveCipher.localSync(f.secret).encrypt(DeterministicCbor.encode(bad, bound), f.binding)
            val savedLocal = local.bytes?.copyOf()
            f.open(Storage(disk), localStorage = Storage(local), clock = { error("Import cannot record a local time") }).use {
                assertEquals(1, it.snapshot().proofs.size); assertNull(it.localSyncTimes())
            }
            assertContentEquals(savedProofs, disk.bytes); assertContentEquals(savedLocal, local.bytes)
        }
    }

}
