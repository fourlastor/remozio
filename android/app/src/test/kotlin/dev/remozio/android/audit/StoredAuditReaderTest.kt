package dev.remozio.android.audit

import dev.remozio.android.enrollment.MacInventoryState
import dev.remozio.android.enrollment.StoredMacReader
import kotlinx.coroutines.sync.Mutex
import dev.remozio.phone.audit.*
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.RelayAccessCredential
import dev.remozio.phone.transport.RelayEndpoint
import dev.remozio.protocol.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.ZoneId
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import org.junit.Test
import kotlin.test.*

class StoredAuditReaderTest {
    private val bound = CborLimits(65536, 8, 1024)
    private val protocol = AuditPageLimits(bound, bound, bound, 8, bound, bound)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun keys() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun aes() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    private class EnrollmentDisk : EnrollmentStorage {
        var bytes: ByteArray? = null
        var writes = 0
        @Volatile var closes = 0
        override fun read(maximumBytes: Int) = bytes?.copyOf()?.also { require(it.size <= maximumBytes) }
        override fun replace(ciphertext: ByteArray) { writes++; bytes = ciphertext.copyOf() }
        override fun close() { closes++ }
    }

    private inner class Fixture {
        val disk = EnrollmentDisk()
        private val cipher = EnrollmentCipher(aes(), bound.maxBytes)
        val enrollment = EncryptedEnrollmentStore.create(disk, cipher, 10)
        var revision = 0uL
        val archives = mutableMapOf<CborValue.Bytes, Archive>()
        fun add(n: Int, active: Boolean = true, removed: Boolean = false, mac: Int = n, authority: KeyPair = keys()): Archive {
            val record = record(n, authority, mac)
            enrollment.prepare(record, revision++)
            if (active) enrollment.activateSyntheticEnrollment(record.recordID.copyBytes(), revision++)
            if (removed) enrollment.remove(record.recordID.copyBytes(), revision++)
            return Archive(record, authority).also { archives[record.recordID] = it }
        }
        fun openEnrollment() = EncryptedEnrollmentStore.open(disk, cipher, 10)
        fun reader(open: ((AuditCacheBinding, Int) -> EncryptedAuditCache?)? = null,
                   budget: AuditReadBudget = AuditReadBudget()) = StoredAuditReader(
            { openEnrollment() },
            open ?: { binding, limit -> archives.values.lastOrNull { it.record.macID == CborValue.Bytes(binding.macID) &&
                it.record.accountID == CborValue.Bytes(binding.accountID) &&
                it.record.authorityPublicKey == CborValue.Bytes(binding.authorityPublicKey) }?.open(binding, limit) }, budget,
        )
    }

    private inner class Archive(val record: PhoneEnrollment, val authority: KeyPair) {
        private val secret = aes()
        var bytes: ByteArray? = null
        var opens = 0
        var closes = 0
        var writes = 0
        fun populate(conflict: Boolean = false, baseReason: AuditReason = AuditReason.NONE) {
            fun proof(reason: AuditReason): CborValue.Fields {
                val events = (1..2).map { sequence ->
                    AuditEventMetadata(id(sequence + 30), record.macID.copyBytes(), record.accountID.copyBytes(), id(50),
                        sequence.toULong(), id(60), (3000 - sequence * 1000).toULong(), null,
                        AuditEventKind.REQUEST_CREATED, AuditCategory.COMMAND, null, null, AuditAuthentication.SYSTEM,
                        AuditOutcome.PENDING, reason, null, null).encode(bound)
                }
                val body = DeterministicCbor.encode(CborValue.Fields(mapOf(
                    0uL to CborValue.Unsigned(1u), 1uL to record.macID, 2uL to record.accountID,
                    3uL to CborValue.Bytes(id(50)), 4uL to CborValue.Unsigned(1u), 5uL to CborValue.Unsigned(0u),
                    6uL to CborValue.Unsigned(0u), 7uL to CborValue.Unsigned(4u), 8uL to CborValue.Bytes(ByteArray(32)),
                    9uL to CborValue.ArrayValue(events.map(CborValue::Bytes)),
                )), bound)
                val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                    initSign(authority.private); update(AuditBatchSigningInput.make(1u, body, bound, bound)); sign()
                })
                return CborValue.Fields(mapOf(0uL to CborValue.Unsigned(1u),
                    1uL to CborValue.Bytes(body), 2uL to CborValue.Bytes(signature)))
            }
            val proofs = listOf(proof(baseReason)) + if (conflict) listOf(proof(AuditReason.UNKNOWN)) else emptyList()
            val plaintext = DeterministicCbor.encode(CborValue.Fields(mapOf(
                0uL to CborValue.Unsigned(1u), 1uL to CborValue.ArrayValue(proofs),
            )), bound)
            bytes = AuditArchiveCipher(secret, bound.maxBytes).encrypt(plaintext,
                AuditCacheBinding(record.macID.copyBytes(), record.accountID.copyBytes(), record.authorityPublicKey.copyBytes()))
        }
        fun open(binding: AuditCacheBinding, limit: Int): EncryptedAuditCache? {
            opens++
            if (bytes == null) return null
            val storage = object : AuditCiphertextStorage {
                override fun read(maximumBytes: Int) = checkNotNull(bytes).copyOf().also { require(it.size <= maximumBytes) }
                override fun replace(ciphertext: ByteArray) { writes++; error("A reader must never write") }
                override fun close() { closes++ }
            }
            return try {
                EncryptedAuditCache.open(storage, AuditArchiveCipher(secret, limit), binding, protocol,
                    AuditEvidenceLimits(20, limit.toLong(), 20, 10), CborLimits(limit, 8, 1024))
            } catch (failure: Throwable) { storage.close(); throw failure }
        }
    }

    @Test fun scopeProjectionKeepsDuplicateLabelsDistinctAndReadsRemovedHistoryWithoutWrites() = runBlocking {
        val f = Fixture()
        val first = f.add(1).also { it.populate() }
        val second = f.add(2, removed = true).also { it.populate() }
        val third = f.add(3).also { it.populate() }
        // Use an actually incomplete setup as a separate scope.
        val incomplete = f.add(4, active = false).also { it.populate() }
        val before = f.disk.writes
        val result = assertIs<StoredAuditState.Ready>(f.reader().read())
        assertEquals(listOf(first.record.macID, second.record.macID, third.record.macID), result.macs.map { it.macID })
        assertEquals(3, result.scopes.size)
        assertTrue(result.macs.all { it.label == "Same display name" })
        assertEquals(0, incomplete.opens)
        assertEquals(before, f.disk.writes)
        assertEquals(0, f.archives.values.sumOf { it.writes })
        assertTrue(result.scopes.all { it.archives.single().content is CachedAuditContent.Loaded })
        assertFailsWith<UnsupportedOperationException> { (result.scopes as MutableList).clear() }
        assertFalse(result.toString().contains("Same display name"))
        f.enrollment.close()
    }

    @Test fun filtersPreserveGapsAndConflictsAndTimelineUsesSequenceInsteadOfClock() = runBlocking {
        val f = Fixture(); val archive = f.add(1).also { it.populate(conflict = true) }
        val reader = f.reader()
        val loaded = assertIs<CachedAuditContent.Loaded>(assertIs<StoredAuditState.Ready>(reader.read()).scopes.single().archives.single().content)
        val epoch = loaded.history.chains.single().epochs.single()
        assertEquals(listOf(2uL, 1uL), epoch.records.map { it.sequence })
        assertEquals(1, loaded.history.conflictingProofCount)
        assertEquals(2uL, epoch.gaps.single().after)
        assertEquals(4uL, epoch.gaps.single().through)
        val filtered = assertIs<CachedAuditContent.Loaded>(assertIs<StoredAuditState.Ready>(
            reader.read(archive.record.macID, outcome = AuditOutcome.UNKNOWN)).scopes.single().archives.single().content)
        assertTrue(filtered.history.chains.single().epochs.single().records.isEmpty())
        assertEquals(1, filtered.history.conflictingProofCount)
        assertEquals(1, filtered.history.chains.single().epochs.single().gaps.size)
        assertEquals(listOf(1uL, 2uL), AuditHistory.timeline(filtered.snapshot, id(60)).chains.single().epochs.single().records.map { it.sequence })
        assertEquals(archive.opens, archive.closes)
        f.enrollment.close()
    }

    @Test fun missingCorruptAndGoodScopesStaySeparateAndErrorsDoNotExposeProviderText() = runBlocking {
        val f = Fixture(); f.add(1)
        f.add(2).bytes = byteArrayOf(1, 2, 3)
        f.add(3).populate()
        val result = assertIs<StoredAuditState.Ready>(f.reader().read())
        assertSame(CachedAuditContent.Missing, result.scopes[0].archives.single().content)
        assertSame(CachedAuditContent.Unavailable, result.scopes[1].archives.single().content)
        assertIs<CachedAuditContent.Loaded>(result.scopes[2].archives.single().content)
        assertSame(StoredAuditState.Unavailable, StoredAuditReader({ error("synthetic-secret") }, { _, _ -> null }).read())
        assertTrue(assertIs<StoredAuditState.Ready>(StoredAuditReader({ null }, { _, _ -> error("unexpected") }).read()).scopes.isEmpty())
        assertEquals(0, f.archives.values.sumOf { it.writes })
        f.enrollment.close()
    }

    @Test fun currentAndFormerAuthorityArchivesRemainVisibleWithoutCrossKeyConflictsOrTimelines() = runBlocking<Unit> {
        val f = Fixture()
        val former = f.add(1, removed = true).also { it.populate(baseReason = AuditReason.UNKNOWN) }
        val current = f.add(2, mac = 1).also { it.populate() }
        val result = assertIs<StoredAuditState.Ready>(f.reader().read())
        val scope = result.scopes.single()
        assertEquals(2, scope.archives.size)
        assertEquals(listOf(current.record.authorityPublicKey, former.record.authorityPublicKey), scope.archives.map { it.authorityPublicKey })
        assertEquals(listOf(false, true), scope.archives.map { it.retired })
        val currentContent = assertIs<CachedAuditContent.Loaded>(scope.archives[0].content)
        val formerContent = assertIs<CachedAuditContent.Loaded>(scope.archives[1].content)
        assertEquals(0, currentContent.history.conflictingProofCount); assertEquals(0, formerContent.history.conflictingProofCount)
        // Both keys signed the same Mac/account, request, event IDs, epoch and sequences. Their timelines stay independent.
        assertTrue(AuditHistory.timeline(currentContent.snapshot, id(60)).chains.single().epochs.single().records.all { it.reason == AuditReason.NONE })
        assertTrue(AuditHistory.timeline(formerContent.snapshot, id(60)).chains.single().epochs.single().records.all { it.reason == AuditReason.UNKNOWN })
        assertNotEquals(scope.archives[0].fingerprint, scope.archives[1].fingerprint)
        assertEquals(64, scope.archives[0].fingerprint.length)
        assertFalse(scope.toString().contains(scope.archives[0].fingerprint))
        assertFailsWith<UnsupportedOperationException> { (scope.archives as MutableList).clear() }
        assertEquals(0, former.writes + current.writes); f.enrollment.close()
    }

    @Test fun aLegacyArchiveWithAnotherRootDoesNotHideOrPretendToPopulateTheCurrentArchive() = runBlocking<Unit> {
        val f = Fixture(); val former = f.add(1, removed = true).also { it.populate() }
        val current = f.add(2, mac = 1)
        val reader = f.reader(open = { binding, limit -> former.open(binding, limit) })
        val archives = assertIs<StoredAuditState.Ready>(reader.read()).scopes.single().archives
        assertEquals(current.record.authorityPublicKey, archives[0].authorityPublicKey)
        assertSame(CachedAuditContent.Unavailable, archives[0].content)
        assertIs<CachedAuditContent.Loaded>(archives[1].content)
        assertEquals(2, former.opens); assertEquals(2, former.closes)
        assertEquals(0, former.writes); f.enrollment.close()
    }

    @Test fun reEnrollmentWithTheSameRootProducesOneArchiveAndPreservesItsActiveLabel() = runBlocking<Unit> {
        val f = Fixture(); val former = f.add(1, removed = true)
        val current = f.add(2, mac = 1, authority = former.authority).also { it.populate() }
        val archive = assertIs<StoredAuditState.Ready>(f.reader().read()).scopes.single().archives.single()
        assertEquals(current.record.authorityPublicKey, archive.authorityPublicKey)
        assertFalse(archive.retired); assertIs<CachedAuditContent.Loaded>(archive.content)
        assertEquals(1, current.opens); assertEquals(0, former.opens); f.enrollment.close()
    }

    @Test fun aCorruptFormerArchiveDoesNotHideTheGoodCurrentArchive() = runBlocking<Unit> {
        val f = Fixture(); val former = f.add(1, removed = true).also { it.bytes = byteArrayOf(1, 2, 3) }
        val current = f.add(2, mac = 1).also { it.populate() }
        val archives = assertIs<StoredAuditState.Ready>(f.reader().read()).scopes.single().archives
        assertIs<CachedAuditContent.Loaded>(archives[0].content)
        assertSame(CachedAuditContent.Unavailable, archives[1].content)
        assertContentEquals(byteArrayOf(1, 2, 3), former.bytes)
        assertEquals(0, former.writes + current.writes); f.enrollment.close()
    }

    @Test fun totalBudgetAppliesAcrossRootsWithoutEvictingTheFormerArchive() = runBlocking<Unit> {
        val f = Fixture(); val former = f.add(1, removed = true).also { it.populate() }
        val current = f.add(2, mac = 1).also { it.populate() }
        val before = checkNotNull(former.bytes).copyOf()
        val first = assertIs<StoredAuditState.Ready>(f.reader().read()).scopes.single().archives
        val size = assertIs<CachedAuditContent.Loaded>(first[0].content).snapshot.storedBytes.toInt()
        val archives = assertIs<StoredAuditState.Ready>(f.reader(budget = AuditReadBudget(size + 128, size + 128)).read()).scopes.single().archives
        assertIs<CachedAuditContent.Loaded>(archives[0].content)
        assertSame(CachedAuditContent.Unavailable, archives[1].content)
        assertContentEquals(before, former.bytes); assertEquals(0, former.writes + current.writes); f.enrollment.close()
    }

    @Test fun readBudgetRejectsOversizedEvidenceWithoutDeletingItAndMacSelectionStillWorks() = runBlocking {
        val f = Fixture(); val first = f.add(1).also { it.populate() }; val second = f.add(2).also { it.populate() }
        val initial = assertIs<StoredAuditState.Ready>(f.reader().read())
        val size = assertIs<CachedAuditContent.Loaded>(initial.scopes[0].archives.single().content).snapshot.storedBytes.toInt()
        val bytes = checkNotNull(second.bytes).copyOf()
        val reader = f.reader(budget = AuditReadBudget(size + 128, size + 128))
        val limited = assertIs<StoredAuditState.Ready>(reader.read())
        assertIs<CachedAuditContent.Loaded>(limited.scopes[0].archives.single().content)
        assertSame(CachedAuditContent.Unavailable, limited.scopes[1].archives.single().content)
        assertIs<CachedAuditContent.Loaded>(assertIs<StoredAuditState.Ready>(reader.read(second.record.macID)).scopes.single().archives.single().content)
        assertContentEquals(bytes, second.bytes)
        assertEquals(0, first.writes + second.writes)
        f.enrollment.close()
    }

    @Test fun cancellationClosesCacheBeforeTheNextReadAndDoesNotPublishLateEvidence() = runBlocking {
        val f = Fixture(); val archive = f.add(1).also { it.populate() }
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val attempts = AtomicInteger()
        val reader = f.reader(open = { binding, limit ->
            if (attempts.incrementAndGet() == 1) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
            else check(archive.closes == 1)
            archive.open(binding, limit)
        })
        var published = false
        val first = launch(Dispatchers.Default) { reader.read(); published = true }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS)); first.cancel()
            val second = async(Dispatchers.Default) { reader.read() }
            release.countDown()
            withTimeout(5000) { first.join(); assertIs<StoredAuditState.Ready>(second.await()) }
            assertFalse(published); assertEquals(2, archive.closes)
        } finally { release.countDown(); first.cancelAndJoin(); f.enrollment.close() }
    }

    @Test fun switchingDestinationsWaitsForCancelledEnrollmentReadToClose() = runBlocking {
        val f = Fixture(); f.add(1).populate()
        val access = Mutex(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val audit = StoredAuditReader({
            entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); f.openEnrollment()
        }, { _, _ -> error("Cancelled audit must not open a cache") }, enrollmentAccess = access)
        val macs = StoredMacReader({ check(f.disk.closes == 1); f.openEnrollment() }, enrollmentAccess = access)
        var published = false
        val reading = launch(Dispatchers.Default) { audit.read(); published = true }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            reading.cancel()
            val inventory = async(Dispatchers.Default) { macs.read() }
            release.countDown()
            withTimeout(5000) {
                reading.join()
                assertEquals(1, assertIs<MacInventoryState.Ready>(inventory.await()).macs.size)
            }
            assertFalse(published)
            assertEquals(2, f.disk.closes)
        } finally { release.countDown(); reading.cancelAndJoin(); f.enrollment.close() }
    }

    @Test fun auditCacheWorkDoesNotHoldTheSharedEnrollmentLock() = runBlocking {
        val f = Fixture(); val archive = f.add(1).also { it.populate() }
        val access = Mutex(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val audit = StoredAuditReader({ f.openEnrollment() }, { binding, limit ->
            entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); archive.open(binding, limit)
        }, enrollmentAccess = access)
        val macs = StoredMacReader({ check(f.disk.closes == 1); f.openEnrollment() }, enrollmentAccess = access)
        val reading = async(Dispatchers.Default) { audit.read() }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            withTimeout(2000) { assertIs<MacInventoryState.Ready>(macs.read()) }
            release.countDown()
            withTimeout(5000) { assertIs<StoredAuditState.Ready>(reading.await()) }
            assertEquals(2, f.disk.closes)
        } finally { release.countDown(); reading.cancelAndJoin(); f.enrollment.close() }
    }

    @Test fun gapRowsKeepTheirSequencePositionsInBothDirectionsAndAfterFiltering() {
        val events = listOf(5, 2, 8).map { sequence ->
            AuditEventMetadata(id(sequence), id(1), id(2), id(3), sequence.toULong(), null, null, null,
                AuditEventKind.REQUEST_CREATED, AuditCategory.COMMAND, null, null, AuditAuthentication.SYSTEM,
                AuditOutcome.PENDING, AuditReason.NONE, null, null)
        }
        val gaps = listOf(AuditHistoryGap(0u, 1u, true), AuditHistoryGap(2u, 4u, false),
            AuditHistoryGap(5u, 7u, false), AuditHistoryGap(8u, ULong.MAX_VALUE, false))
        fun labels(rows: List<AuditRow>) = rows.map { when (it) {
            is AuditRow.Event -> "event ${it.value.sequence}"
            is AuditRow.Gap -> "gap ${it.value.after}"
        } }
        val ascending = listOf("gap 0", "event 2", "gap 2", "event 5", "gap 5", "event 8", "gap 8")
        assertEquals(ascending, labels(auditRows(events, gaps, newestFirst = false)))
        assertEquals(ascending.reversed(), labels(auditRows(events, gaps, newestFirst = true)))
        assertEquals(listOf("gap 0", "gap 2", "event 5", "gap 5", "gap 8"),
            labels(auditRows(events.filter { it.sequence == 5uL }, gaps, newestFirst = false)))
        assertEquals(listOf("gap 8", "gap 5", "gap 2", "gap 0"), labels(auditRows(emptyList(), gaps, newestFirst = true)))
    }

    @Test fun unknownEpochCauseNeverBecomesAKnownRecoveryExplanation() {
        assertEquals(dev.remozio.android.R.string.audit_unknown, auditLabel(AuditEpochCause.UNKNOWN))
        assertEquals(AuditEpochCause.entries.size, AuditEpochCause.entries.map(::auditLabel).toSet().size)
        assertNotEquals(auditLabel(AuditEpochCause.REPLACEMENT), auditLabel(AuditEpochCause.RESTORATION))
    }

    @Test fun unsupportedTimesAreAbsentInsteadOfOverflowingIntoPlausibleDates() {
        val utc = ZoneId.of("UTC")
        assertNull(auditTime(null, utc)); assertNull(auditTime(ULong.MAX_VALUE, utc))
        assertNull(auditTime(Long.MAX_VALUE.toULong(), utc))
        assertNotNull(auditTime(0u, utc))
        assertNotEquals(auditTime(0u, utc), auditTime(0u, ZoneId.of("Pacific/Honolulu")))
    }

    private fun record(n: Int, authority: KeyPair, mac: Int): PhoneEnrollment {
        fun key(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val public = keys().public.encoded
            return EnrollmentKeyReference(role, id(n * 3 + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(n * 3 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) public else public.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(mac), id(100), id(n + 40), id(n + 80), "Same display name",
            authority.public.encoded.takeLast(65).toByteArray(), keys().public.encoded,
            key(EnrollmentKeyRole.TRANSPORT), key(EnrollmentKeyRole.DECISION), key(EnrollmentKeyRole.BIOMETRIC),
            ByteArray(32) { n.toByte() }, RelayAccessCredential(RelayEndpoint("synthetic.example"), "synthetic-id", "synthetic-secret"))
    }

    @Test fun retainedLocalDatesStayWithTheirRootArchiveThroughFilteringWithoutReadsOrTrustClaims() = runBlocking<Unit> {
        val f = Fixture(); val former = f.add(1, removed = true).also { it.populate(baseReason = AuditReason.UNKNOWN) }
        val current = f.add(2, mac = 1).also { it.populate() }
        val snapshots = listOf(former, current).associate { archive ->
            val record = archive.record
            val binding = AuditCacheBinding(record.macID.copyBytes(), record.accountID.copyBytes(), record.authorityPublicKey.copyBytes())
            record.authorityPublicKey to checkNotNull(archive.open(binding, bound.maxBytes)).use { it.snapshot() }
        }
        // Synthetic local display metadata; cipher and fresh-receiver qualification live in phone-core tests.
        val dates = listOf(former, current).mapIndexed { index, archive -> archive.record.authorityPublicKey to
            AuditLocalSyncTime(1_790_000_000_000L + index * 1000, CborValue.Bytes(ByteArray(32) { index.toByte() })) }.toMap()
        val reader = StoredAuditReader(f::openEnrollment, { _, _ -> error("Owned snapshots cannot reopen files") },
            readSnapshot = { binding, _ ->
                val root = CborValue.Bytes(binding.authorityPublicKey)
                AuditRetainedSnapshot(snapshots.getValue(root), AuditLocalSyncTimes(dates.getValue(root), dates.getValue(root)))
            })
        val loaded = assertIs<StoredAuditState.Ready>(reader.read(outcome = AuditOutcome.ACCEPTED)).scopes.single().archives
        assertEquals(listOf(current.record.authorityPublicKey, former.record.authorityPublicKey), loaded.map { it.authorityPublicKey })
        loaded.forEach { archive ->
            val content = assertIs<CachedAuditContent.Loaded>(archive.content)
            assertSame(snapshots.getValue(archive.authorityPublicKey), content.snapshot)
            assertEquals(dates.getValue(archive.authorityPublicKey), content.localTimes?.lastCompleted)
            assertTrue(content.history.chains.flatMap { it.epochs }.all { it.records.isEmpty() })
        }
        assertEquals(0, former.writes + current.writes); f.enrollment.close()
    }

}
