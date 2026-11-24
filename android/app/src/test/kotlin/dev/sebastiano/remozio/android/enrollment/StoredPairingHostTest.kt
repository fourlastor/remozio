package dev.sebastiano.remozio.android.enrollment

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.RelayAccessCredential
import dev.remozio.phone.transport.RelayEndpoint
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.junit.Test
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class StoredPairingHostTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val authority = key()
    private val biometric = key()
    private fun record(n: Int, mac: Int = 20, relay: RelayAccessCredential? = null): PhoneEnrollment {
        val localBiometric = if (mac == 20) biometric else key()
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val point = (if (role == EnrollmentKeyRole.BIOMETRIC) localBiometric else key()).public.encoded
            return EnrollmentKeyReference(role, id(n * 3 + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(n * 3 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) point else point.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(mac), id(21), id(n + 30), id(n + 40), "Synthetic Mac",
            authority.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION), local(EnrollmentKeyRole.BIOMETRIC),
            ByteArray(32) { n.toByte() }, relay)
    }
    private fun transcript(e: PhoneEnrollment, old: PhoneEnrollment? = null): PairingTranscript {
        val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
        fun offer(role: ChannelRole, nonce: Int) = ChannelOffer(role, scope, ByteArray(32) { nonce.toByte() }, setOf(1uL), emptyList(), emptySet())
        fun claim(k: EnrollmentKeyReference) = PairingKey(k.keyID.copyBytes(), k.publicKey.copyBytes().takeLast(65).toByteArray())
        return PairingTranscript(id(70), ByteArray(32) { 71 }, offer(ChannelRole.PHONE, 72), offer(ChannelRole.MAC, 73),
            1u, 1u, e.authorityPublicKey.copyBytes(), e.transportPublicKey.copyBytes().takeLast(65).toByteArray(),
            claim(e.transportKey), claim(e.decisionKey), claim(e.biometricKey), e.enrollmentTag.copyBytes(),
            old?.let { PairingReplacement(it.phoneID.copyBytes(), it.epoch.copyBytes()) }, id(74), 1000u, 2000u)
    }

    private class Storage : EnrollmentStorage {
        var bytes: ByteArray? = null
        var fail = false
        var failRead = false
        var replacements = 0
        var beforeRead: () -> Unit = {}
        var beforeReplace: () -> Unit = {}
        override fun read(maximumBytes: Int): ByteArray? {
            beforeRead()
            check(!failRead)
            return bytes?.copyOf()
        }
        override fun replace(ciphertext: ByteArray) {
            check(!fail)
            beforeReplace()
            bytes = ciphertext.copyOf()
            replacements++
        }
        override fun close() = Unit
    }
    private val storage = Storage()
    private val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65536)
    private val mutex = Mutex()
    private var custodyAvailable = true
    private var custodyChecks = 0
    private var afterCustodyCheck: () -> Unit = {}
    private val invalidated = mutableListOf<Set<CborValue.Bytes>>()
    private fun open() = EncryptedEnrollmentStore.open(storage, cipher, 10)
    private fun host(invalidate: (Set<CborValue.Bytes>) -> Unit = { invalidated.add(it) }) = StoredPairingHost(
        ::open, ::open, mutex, { assertTrue(mutex.isLocked); invalidate(it) }, { custodyChecks++; check(custodyAvailable); afterCustodyCheck() }, Dispatchers.Unconfined)
    private fun receipt(t: PairingTranscript) = CborValue.Bytes(P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
        initSign(authority.private); update(t.signingInput(PairingProofPurpose.MAC_COMMIT)); sign()
    }))
    init { EncryptedEnrollmentStore.create(storage, cipher, 10).close() }

    private class RecoveryWire(
        private val read: suspend () -> ByteArray?,
        private val joining: suspend () -> Unit = {},
    ) : PairingReceiptWire {
        var queries = 0
        var joins = 0
        override suspend fun recover(): ByteArray? { queries++; return read() }
        override fun close() = Unit
        override suspend fun closeAndJoin() { joins++; joining() }
    }

    private class RePairWire(
        private val read: suspend () -> PairingRecoveryFrame.Reply,
        private val joining: suspend () -> Unit = {},
    ) : RePairRecoveryWire {
        var lookups = 0
        var joins = 0

        override suspend fun lookup(): PairingRecoveryFrame.Reply { lookups++; return read() }
        override suspend fun closeAndJoin() { joins++; joining() }
    }

    private class RePairKeys : RePairKeyCleanup {
        val allocated = mutableSetOf<String>()
        val publicKeys = mutableMapOf<String, CborValue.Bytes>()
        val retired = mutableListOf<String>()
        val retirementAttempts = mutableListOf<String>()
        var beforeRetire: () -> Unit = {}
        override fun contains(alias: String) = alias in allocated

        fun allocate(keys: List<EnrollmentKeyReference>) {
            for (key in keys) {
                allocated.add(key.alias)
                publicKeys[key.alias] = key.publicKey
            }
        }

        override fun retire(alias: String, expectedPublicKey: CborValue.Bytes?) {
            retirementAttempts.add(alias)
            beforeRetire()
            if (expectedPublicKey != null && publicKeys[alias] != expectedPublicKey) return
            if (allocated.remove(alias)) {
                publicKeys.remove(alias)
                retired.add(alias)
            }
        }
    }

    private fun rePairHost(keys: RePairKeys, onChanged: () -> Unit = {}) = StoredPairingHost(
        ::open, ::open, mutex, { invalidated.add(it) }, {}, Dispatchers.Unconfined, rePairKeys = keys, onChanged = onChanged,
    )

    private fun envelope(old: PhoneEnrollment, transport: ByteArray = old.transportPublicKey.copyBytes().takeLast(65).toByteArray()) =
        RePairInvitation(PairingInvitation(old.macID.copyBytes(), old.accountID.copyBytes(), old.label,
            old.authorityPublicKey.copyBytes(), transport, 1u),
            PairingReplacement(old.phoneID.copyBytes(), old.epoch.copyBytes()))

    private suspend fun activatePredecessor(h: StoredPairingHost, old: PhoneEnrollment) {
        val t = transcript(old)
        h.prepare(old, t, 0u, 1u)
        h.activate(old.recordID, receipt(t))
    }

    private fun proposalFor(reservation: RePairReservation): Pair<RePairProposalMaterial, PairingTranscript> {
        val invitation = reservation.invitation
        val keys = EnrollmentKeyRole.entries.map { role ->
            val spki = key().public.encoded
            EnrollmentKeyReference(role, reservation.keyIDs[role.ordinal].copyBytes(), reservation.alias(role),
                if (role == EnrollmentKeyRole.TRANSPORT) spki else spki.takeLast(65).toByteArray())
        }
        val scope = ChannelScope(invitation.invitation.macID.copyBytes(), invitation.invitation.accountID.copyBytes(),
            invitation.predecessor.phoneID.copyBytes(), reservation.epoch.copyBytes())
        fun offer(role: ChannelRole, nonce: Int) =
            ChannelOffer(role, scope, ByteArray(32) { nonce.toByte() }, setOf(1u), emptyList(), emptySet())
        fun claim(key: EnrollmentKeyReference) =
            PairingKey(key.keyID.copyBytes(), key.publicKey.copyBytes().takeLast(65).toByteArray())
        val proposal = PairingPhoneProposal(offer(ChannelRole.PHONE, 82), claim(keys[0]), claim(keys[1]), claim(keys[2]),
            invitation.predecessor)
        val transcript = PairingTranscript(id(80), ByteArray(32) { 81 }, proposal.phone, offer(ChannelRole.MAC, 83),
            1u, 1u, invitation.invitation.authorityPublicKey.copyBytes(), invitation.invitation.transportPublicKey.copyBytes(),
            proposal.transportKey, proposal.decisionKey, proposal.biometricKey, ByteArray(32) { 84 },
            invitation.predecessor, id(85), 1000u, 2000u)
        return RePairProposalMaterial(proposal, keys) to transcript
    }

    @Test fun rePairRequiresExactRetainedPinsAndSerializesBeforeKeyAllocation() = runBlocking {
        val keys = RePairKeys()
        val h = rePairHost(keys)
        val old = record(1)
        activatePredecessor(h, old)
        assertFails { h.inspectRePair(envelope(old, key().public.encoded.takeLast(65).toByteArray())) }
        assertEquals(old.recordID, h.inspectRePair(envelope(old)).enrollment.recordID)
        val outcomes = (0..1).map { n ->
            async { runCatching { h.reserveRePair(envelope(old), id(30 + n), id(60 + n),
                List(3) { CborValue.Bytes(id(92 + n * 3 + it)) }) } }
        }.map { it.await() }
        assertEquals(1, outcomes.count { it.isSuccess })
        assertIs<RePairAlreadyPending>(outcomes.single { it.isFailure }.exceptionOrNull())
        open().use { assertEquals(1, it.snapshot().rePairReservations.size) }
        assertTrue(keys.allocated.isEmpty())
    }

    @Test fun androidAttemptReservesTheDurableSlotBeforeItsFirstHardwareKeyRequest() = runBlocking {
        val keys = RePairKeys()
        val h = rePairHost(keys)
        val old = record(1)
        activatePredecessor(h, old)
        val invited = envelope(old).exportText()
        var allocations = 0
        val providerFailure = IllegalStateException("Stop at the first hardware allocation")
        val parent = CoroutineScope(checkNotNull(currentCoroutineContext()[Job]))
        fun attempt() = AndroidPairingAttempt(parent, h, { error("Unexpected Android context access") }) { _, keyID ->
            allocations++
            open().use {
                val pending = it.snapshot().rePairReservations.single()
                assertEquals(old.recordID, pending.predecessorRecordID)
                assertContentEquals(pending.keyIDs[EnrollmentKeyRole.TRANSPORT.ordinal].copyBytes(), keyID)
                assertNull(pending.material)
            }
            throw providerFailure
        }
        val first = attempt()
        val second = attempt()
        try {
            val failure = assertFailsWith<IllegalStateException> { first.connect(invited) }
            assertEquals(providerFailure.message, failure.message)
            assertFailsWith<RePairAlreadyPending> { second.connect(invited) }
            assertEquals(1, allocations)
        } finally {
            second.closeAndJoin()
            first.closeAndJoin()
        }
        open().use { assertTrue(it.snapshot().rePairReservations.isEmpty()) }
        val bytes = cipher.decrypt(checkNotNull(storage.bytes))
        val encoded = assertIs<CborValue.Fields>(DeterministicCbor.decode(bytes, CborLimits(65_536, 8, 1_016)))
        assertEquals(CborValue.Unsigned(3u), encoded.values[0u])
    }

    @Test fun startupReconciliationCleansAnAbandonedReservationWithoutOpeningInventory() = runBlocking {
        val keys = RePairKeys()
        val h = rePairHost(keys)
        val old = record(1)
        activatePredecessor(h, old)
        val reservation = h.reserveRePair(envelope(old), id(30), id(60), List(3) { CborValue.Bytes(id(92 + it)) })
        val unrelated = old.transportKey.alias
        keys.allocated.add(unrelated)
        keys.allocated.add(reservation.alias(EnrollmentKeyRole.TRANSPORT))
        assertFails { h.recoverable(reservation.recordID) }
        assertFailsWith<RePairAlreadyPending> { h.inspectRePair(envelope(old)) }
        val reopened = rePairHost(keys)
        reopened.reconcileRePairOnStartup()
        assertEquals(listOf(reservation.alias(EnrollmentKeyRole.TRANSPORT)), keys.retired)
        assertEquals(setOf(unrelated), keys.allocated)
        open().use { assertTrue(it.snapshot().rePairReservations.isEmpty()) }
        val attempts = keys.retirementAttempts.toList()
        reopened.reconcileRePairOnStartup()
        assertEquals(attempts, keys.retirementAttempts)
        assertEquals(old.recordID, reopened.inspectRePair(envelope(old)).enrollment.recordID)
    }

    @Test fun rePairCheckpointFailureRetainsProposalAndRestartDrainsUnsubmittedKeys() = runBlocking {
        val keys = RePairKeys()
        val h = rePairHost(keys)
        val old = record(1)
        activatePredecessor(h, old)
        val reservation = h.reserveRePair(envelope(old), id(30), id(60), List(3) { CborValue.Bytes(id(92 + it)) })
        val (material, t) = proposalFor(reservation)
        keys.allocate(material.keys)
        h.prepareRePairProposal(reservation.recordID, material)
        assertFails { h.checkpointRePair(reservation.recordID, transcript(old)) }
        storage.fail = true
        assertFailsWith<EnrollmentStoreUnavailable> { h.checkpointRePair(reservation.recordID, t) }
        storage.fail = false
        open().use {
            val pending = it.snapshot().rePairReservations.single()
            assertContentEquals(material.proposal.encode(), pending.material?.proposal?.encode())
            assertEquals(reservation.keyIDs, pending.keyIDs)
            assertEquals(old.recordID, it.snapshot().entries.single().enrollment.recordID)
        }
        rePairHost(keys).reconcileRePairOnStartup()
        assertEquals(material.keys.map { it.alias }.toSet(), keys.retired.toSet())
    }

    @Test fun rePairProofMarkerSurvivesRestartAndReceiptRetiresTheExactRemovedPredecessor(): Unit = runTest {
        val keys = RePairKeys()
        val h = rePairHost(keys)
        val old = record(1)
        activatePredecessor(h, old)
        h.remove(old.recordID, 2u)
        val invitation = envelope(old)
        val reservation = h.reserveRePair(invitation, id(30), id(60), List(3) { CborValue.Bytes(id(92 + it)) })
        val (material, t) = proposalFor(reservation)
        keys.allocate(material.keys)
        h.prepareRePairProposal(reservation.recordID, material)
        h.checkpointRePair(reservation.recordID, t)
        val access = h.prepared(reservation.recordID, t)
        assertFalse(checkNotNull(access.record.rePair).proofMayHaveBeenSent)
        h.markRePairProof(access)
        h.release(reservation.recordID, access.lease)
        val reopened = rePairHost(keys)
        reopened.reconcileRePairOnStartup()
        assertTrue(keys.retired.isEmpty())
        assertFailsWith<RePairAlreadyPending> { reopened.inspectRePair(invitation) }
        fun recovery(open: suspend (CoroutineScope, PreparedPairingAccess, Long) -> RePairRecoveryWire) =
            PairingReceiptRecovery(reopened, { _, _ -> fail("Re-pair opened enrolled receipt transport") },
                StandardTestDispatcher(testScheduler), openRePair = open, clock = testScheduler.timeSource)
        assertEquals(PairingReceiptOutcome.INCONCLUSIVE, recovery { _, _, _ -> RePairWire({ PairingRecoveryFrame.Refused }) }.recover(reservation.recordID))
        assertEquals(PairingReceiptOutcome.INCONCLUSIVE, recovery { _, _, _ -> error("Recovery transport closed") }.recover(reservation.recordID))
        val wrong = PairingRecoveryFrame.Committed(receipt(transcript(old)).copyBytes())
        assertEquals(PairingReceiptOutcome.INCONCLUSIVE, recovery { _, _, _ -> RePairWire({ wrong }) }.recover(reservation.recordID))
        val wire = RePairWire({ PairingRecoveryFrame.Committed(receipt(t).copyBytes()) })
        val recovered = recovery { _, access, _ ->
            val row = access.record
            assertContentEquals(t.encode(), checkNotNull(row.pairing).transcript.encode())
            assertEquals(material.keys[0].alias, row.enrollment.transportKey.alias)
            wire
        }
        assertEquals(PairingReceiptOutcome.RESOLVED, recovered.recover(reservation.recordID))
        assertEquals(PairingReceiptOutcome.RESOLVED, recovered.recover(reservation.recordID))
        assertEquals(1, wire.lookups)
        assertEquals(1, wire.joins)
        open().use { store ->
            val snapshot = store.snapshot()
            assertEquals(reservation.recordID, snapshot.entries.single { it.enrollment.recordID == old.recordID }.successorRecordID)
            assertEquals(old.phoneID, snapshot.entries.single { it.phase == EnrollmentPhase.ACTIVE }.enrollment.phoneID)
            store.remove(reservation.recordID.copyBytes(), snapshot.revision)
        }
        assertFails { reopened.inspectRePair(invitation) }
    }

    @Test fun committedRePairSucceedsAndInventoryRemainsReadableWhenKeyCleanupFails() = runBlocking {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val previous = record(1)
        activatePredecessor(host, previous)
        host.remove(previous.recordID, 2u)
        val reservation = host.reserveRePair(envelope(previous), id(30), id(60), List(3) { CborValue.Bytes(id(92 + it)) })
        val (material, transcript) = proposalFor(reservation)
        keys.allocate(listOf(previous.transportKey))
        keys.allocate(material.keys)
        host.prepareRePairProposal(reservation.recordID, material)
        host.checkpointRePair(reservation.recordID, transcript)
        val access = host.markRePairProof(host.prepared(reservation.recordID, transcript))

        keys.beforeRetire = { error("Synthetic key retirement failure") }
        try {
            val committed = host.activate(reservation.recordID, receipt(transcript), expected = access)
            assertEquals(reservation.recordID, committed.entries.single { it.phase == EnrollmentPhase.ACTIVE }.enrollment.recordID)
        } finally {
            host.release(reservation.recordID, access.lease)
            host.finishRePair(reservation.recordID)
        }
        assertTrue(keys.retirementAttempts.isNotEmpty())
        assertTrue(keys.retired.isEmpty())

        val attempts = keys.retirementAttempts.toList()
        val reader = StoredMacReader(::open, Dispatchers.Unconfined, mutex)
        val revision = open().use { it.snapshot().revision }
        repeat(2) {
            val visible = assertIs<MacInventoryState.Ready>(reader.read()).macs.single()
            assertEquals(reservation.recordID, visible.recordID)
            assertEquals(revision, visible.revision)
            assertFalse(visible.setupIncomplete)
        }
        assertEquals(attempts, keys.retirementAttempts)
        keys.beforeRetire = {}
        val reopened = rePairHost(keys)
        reopened.reconcileRePairOnStartup()
        assertEquals(listOf(previous.transportKey.alias), keys.retired)
        assertEquals(material.keys.map { it.alias }.toSet(), keys.allocated)
        val finished = keys.retirementAttempts.toList()
        reopened.reconcileRePairOnStartup()
        assertEquals(finished, keys.retirementAttempts)
    }

    @Test fun ordinaryPairingAllowsExplicitLocalAbandonmentWithoutReplayingThePendingSetup() = runBlocking {
        val keys = RePairKeys()
        var changeCount = 0
        val h = rePairHost(keys) { changeCount++ }
        val old = record(1)
        activatePredecessor(h, old)
        h.remove(old.recordID, 2u)
        val reservation = h.reserveRePair(envelope(old), id(30), id(60), List(3) { CborValue.Bytes(id(92 + it)) })
        val (material, t) = proposalFor(reservation)
        val pendingAliases = material.keys.map { it.alias }.toSet()
        keys.allocate(material.keys)
        h.prepareRePairProposal(reservation.recordID, material)
        h.checkpointRePair(reservation.recordID, t)
        val access = h.prepared(reservation.recordID, t)
        h.markRePairProof(access)
        h.release(reservation.recordID, access.lease)
        h.finishRePair(reservation.recordID)
        val pendingRevision = open().use { it.snapshot().revision }
        assertFails { h.abandonAmbiguousRePair(reservation.recordID, pendingRevision) }
        assertTrue(keys.retired.isEmpty())

        val ordinary = record(2)
        val ordinaryTranscript = transcript(ordinary)
        keys.allocate(listOf(ordinary.transportKey))
        h.prepare(ordinary, ordinaryTranscript, pendingRevision, 1u)
        val paired = h.activate(ordinary.recordID, receipt(ordinaryTranscript))
        assertNotEquals(old.phoneID, ordinary.phoneID)
        assertTrue(storedMacs(paired).macs.single { it.recordID == reservation.recordID }.canAbandonRePair)
        assertFails { h.abandonAmbiguousRePair(reservation.recordID, pendingRevision) }
        val recovering = h.recoverable(reservation.recordID)
        try {
            assertFails { h.abandonAmbiguousRePair(reservation.recordID, paired.revision) }
            assertTrue(keys.retired.isEmpty())
        } finally { h.release(reservation.recordID, recovering.lease) }

        invalidated.clear()
        val notificationsBeforeAbandonment = changeCount
        val abandoned = h.abandonAmbiguousRePair(reservation.recordID, paired.revision)
        assertEquals(listOf(setOf(reservation.recordID)), invalidated)
        assertEquals(notificationsBeforeAbandonment + 1, changeCount)
        assertEquals(ordinary.recordID, abandoned.entries.single { it.phase == EnrollmentPhase.ACTIVE }.enrollment.recordID)
        val retained = abandoned.entries.single { it.enrollment.recordID == reservation.recordID }
        assertEquals(EnrollmentPhase.REMOVED, retained.phase)
        assertTrue(checkNotNull(retained.rePair).proofMayHaveBeenSent)
        assertNull(abandoned.entries.first().successorRecordID)
        assertEquals(pendingAliases, keys.retired.toSet())
        assertEquals(setOf(ordinary.transportKey.alias), keys.allocated)
        val recovery = PairingReceiptRecovery(h, { _, _ -> fail("Abandoned setup opened receipt transport") }, Dispatchers.Unconfined)
        assertFailsWith<IllegalArgumentException> { recovery.recover(reservation.recordID) }
        val next = h.reserveRePair(envelope(ordinary), id(31), id(61), List(3) { CborValue.Bytes(id(96 + it)) })
        assertEquals(ordinary.recordID, next.predecessorRecordID)
        h.finishRePair(next.recordID)
    }

    private suspend fun submittedRePair(host: StoredPairingHost, keys: RePairKeys,
        predecessor: PhoneEnrollment = record(1),
    ): StoredPhoneEnrollment {
        activatePredecessor(host, predecessor)
        val reservation = host.reserveRePair(envelope(predecessor), id(30), id(60), List(3) { CborValue.Bytes(id(92 + it)) })
        val (material, transcript) = proposalFor(reservation)
        keys.allocate(material.keys + listOf(predecessor.transportKey, predecessor.decisionKey, predecessor.biometricKey))
        host.prepareRePairProposal(reservation.recordID, material)
        host.checkpointRePair(reservation.recordID, transcript)
        val lease = host.prepared(reservation.recordID, transcript)
        val marked = host.markRePairProof(lease).record
        host.release(reservation.recordID, lease.lease)
        host.finishRePair(reservation.recordID)
        return marked
    }

    private fun aliases(enrollment: PhoneEnrollment): Set<String> =
        setOf(enrollment.transportKey.alias, enrollment.decisionKey.alias, enrollment.biometricKey.alias)

    private fun expiry(row: StoredPhoneEnrollment, reason: PairingExpiryReason = PairingExpiryReason.DEADLINE_ELAPSED,
        signer: java.security.KeyPair = authority,
    ): PairingExpiryReceipt {
        val transcript = requireNotNull(row.pairing).transcript
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signer.private)
            update(PairingExpiryReceipt.signingInput(transcript, reason))
            P256SignatureEncoding.fromDer(sign())
        }
        return PairingExpiryReceipt(transcript, reason, signature)
    }

    @Test fun rePairRefusalAndClosureExhaustRetriesWithoutRetirement() = runTest {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val row = submittedRePair(host, keys)
        val archive = checkNotNull(storage.bytes).copyOf()
        val aliases = keys.allocated.toSet()
        val startTimes = mutableListOf<Long>()
        val wires = mutableListOf<RePairWire>()
        val recovery = PairingReceiptRecovery(host, { _, _ -> fail("Enrolled path used") },
            StandardTestDispatcher(testScheduler), openRePair = { _, access, _ ->
                assertTrue(access.record.sameConnectionAs(row))
                startTimes += testScheduler.currentTime
                RePairWire({
                    if (startTimes.size == 2) throw java.io.IOException("Simulated closure")
                    PairingRecoveryFrame.Refused
                }).also { wires.add(it) }
            }, clock = testScheduler.timeSource)
        assertEquals(PairingReceiptOutcome.INCONCLUSIVE, recovery.recover(row.enrollment.recordID))
        assertEquals(listOf(0L, 1_000L, 3_000L), startTimes)
        assertTrue(wires.all { it.joins == 1 && it.lookups == 1 })
        assertEquals(aliases, keys.allocated)
        assertTrue(keys.retired.isEmpty())
        assertContentEquals(archive, storage.bytes)
    }

    @Test fun signedExpiryAfterRefusalJoinsBeforeCommittingAndRetiresOnlyTheCandidate() = runTest {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val predecessor = record(1)
        val row = submittedRePair(host, keys, predecessor)
        val id = row.enrollment.recordID
        var opened = 0
        var joined = 0
        storage.beforeReplace = { assertEquals(3, joined) }
        keys.beforeRetire = {
            assertEquals(3, joined)
            open().use { store ->
                assertEquals(EnrollmentPhase.REMOVED, store.snapshot().entries.single { it.enrollment.recordID == id }.phase)
            }
        }
        val recovery = PairingReceiptRecovery(host, { _, _ -> fail("Enrolled path used") },
            StandardTestDispatcher(testScheduler), openRePair = { _, _, _ ->
                val response = when (++opened) {
                    1 -> PairingRecoveryFrame.Refused
                    2 -> PairingRecoveryFrame.Expired(expiry(row, signer = key()))
                    else -> PairingRecoveryFrame.Expired(expiry(row, PairingExpiryReason.RETIRED_INCARNATION))
                }
                RePairWire({ response }, { joined++ })
            }, clock = testScheduler.timeSource)
        assertEquals(PairingReceiptOutcome.RESOLVED, recovery.recover(id))
        assertEquals(3, opened)
        val snapshot = open().use { it.snapshot() }
        assertEquals(EnrollmentPhase.ACTIVE, snapshot.entries.single { it.enrollment.recordID == predecessor.recordID }.phase)
        assertEquals(aliases(row.enrollment), keys.retired.toSet())
        assertEquals(aliases(predecessor), keys.allocated)
    }

    @Test fun cancellationWhileJoiningRecoveryKeepsTheLeaseAndPreparation() = runTest {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val row = submittedRePair(host, keys)
        val id = row.enrollment.recordID
        val joined = CompletableDeferred<Unit>()
        val releaseJoin = CompletableDeferred<Unit>()
        val recovery = PairingReceiptRecovery(host, { _, _ -> fail("Enrolled path used") },
            StandardTestDispatcher(testScheduler), openRePair = { _, _, _ ->
                RePairWire({ PairingRecoveryFrame.Expired(expiry(row)) }, { joined.complete(Unit); releaseJoin.await() })
            }, clock = testScheduler.timeSource)
        val action = async { recovery.recover(id) }
        joined.await()
        action.cancel()
        assertEquals(PairingReceiptOutcome.IN_PROGRESS, recovery.recover(id))
        releaseJoin.complete(Unit)
        action.join()
        assertTrue(keys.retired.isEmpty())
        val retry = host.recoverable(id)
        assertTrue(retry.record.sameConnectionAs(row))
        host.release(id, retry.lease)
    }

    @Test fun cancellationOnEitherSideOfTheExpiryCommitKeepsTheArchiveAndKeysConsistent() = runTest {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val predecessor = record(1)
        val row = submittedRePair(host, keys, predecessor)
        val candidate = row.enrollment.recordID
        val candidateKeys = aliases(row.enrollment)
        val before = checkNotNull(storage.bytes).copyOf()
        val writes = storage.replacements
        val revision = open().use { it.snapshot().revision }
        val proof = PairingRecoveryFrame.Expired(expiry(row))
        fun phase() = open().use { store -> store.snapshot().entries.single { it.enrollment.recordID == candidate }.phase }
        fun recovery(afterJoin: () -> Unit = {}) = PairingReceiptRecovery(host, { _, _ -> fail("Enrolled path used") },
            StandardTestDispatcher(testScheduler), openRePair = { _, _, _ ->
                RePairWire({ proof }, { afterJoin() })
            }, clock = testScheduler.timeSource)

        var beforeCommit = false
        val first = async(start = CoroutineStart.LAZY) {
            recovery {
                storage.beforeRead = {
                    storage.beforeRead = {}
                    beforeCommit = true
                    coroutineContext.cancel()
                }
            }.recover(candidate)
        }
        first.start()
        first.join()
        assertTrue(beforeCommit && first.isCancelled)
        assertContentEquals(before, storage.bytes)
        assertEquals(writes, storage.replacements)
        assertEquals(EnrollmentPhase.PREPARED, phase())
        assertEquals(aliases(predecessor) + candidateKeys, keys.allocated)
        assertTrue(keys.retirementAttempts.isEmpty())

        var commitEntered = false
        val second = async(start = CoroutineStart.LAZY) {
            storage.beforeReplace = {
                check(!commitEntered)
                commitEntered = true
                coroutineContext.cancel()
                assertContentEquals(before, storage.bytes)
                assertEquals(aliases(predecessor) + candidateKeys, keys.allocated)
            }
            recovery().recover(candidate)
        }
        keys.beforeRetire = {
            assertEquals(writes + 1, storage.replacements)
            assertEquals(EnrollmentPhase.REMOVED, phase())
        }
        second.start()
        second.join()
        assertTrue(commitEntered && second.isCancelled)
        assertEquals(writes + 1, storage.replacements)
        assertEquals(EnrollmentPhase.REMOVED, phase())
        assertEquals(revision + 1u, open().use { it.snapshot().revision })
        assertEquals(candidateKeys, keys.retired.toSet())
        assertEquals(candidateKeys.size, keys.retired.size)
        assertEquals(aliases(predecessor), keys.allocated)
    }

    @Test fun failedArchiveReplacementNeverAuthorizesKeyRetirement() = runBlocking<Unit> {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val row = submittedRePair(host, keys)
        val lease = host.recoverable(row.enrollment.recordID)
        storage.fail = true
        assertFailsWith<EnrollmentStoreUnavailable> { host.retireExpiredRePair(lease, expiry(row)) {} }
        storage.fail = false
        host.release(row.enrollment.recordID, lease.lease)
        host.reconcileRePairOnStartup()
        assertTrue(keys.retirementAttempts.isEmpty())
        assertTrue(open().use { it.snapshot().entries.single { entry -> entry.enrollment.recordID == row.enrollment.recordID } }.sameConnectionAs(row))
    }

    @Test fun unreadableArchiveDefersInterruptedCleanupUntilCommittedSnapshotCanBeRead() = runBlocking<Unit> {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val predecessor = record(1)
        val row = submittedRePair(host, keys, predecessor)
        val expected = expiry(row)
        open().use { store -> store.retireExpiredRePair(row, expected, store.snapshot().revision) }
        val writes = storage.replacements
        val archive = checkNotNull(storage.bytes).copyOf()
        val alreadyDeleted = row.enrollment.transportKey.alias
        assertTrue(keys.allocated.remove(alreadyDeleted))
        val rebooted = rePairHost(keys)
        storage.failRead = true
        rebooted.reconcileRePairOnStartup()
        assertTrue(keys.retirementAttempts.isEmpty())
        assertEquals(writes, storage.replacements)
        assertContentEquals(archive, storage.bytes)
        storage.failRead = false
        rebooted.reconcileRePairOnStartup()
        rebooted.reconcileRePairOnStartup()
        assertEquals(aliases(row.enrollment) - alreadyDeleted, keys.retirementAttempts.toSet())
        assertEquals(2, keys.retirementAttempts.size)
        assertEquals(aliases(predecessor), keys.allocated)
        assertEquals(writes, storage.replacements)
    }

    @Test fun revokingThePredecessorClosesRelayAndNextDirectAttemptRetiresTheCandidate() = runTest {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val old = record(1, relay = RelayAccessCredential(RelayEndpoint("synthetic.example"), "fixture-id", "fixture-secret"))
        val row = submittedRePair(host, keys, old)
        val id = row.enrollment.recordID
        val relayEntered = CompletableDeferred<RecoveryRelayAccess>()
        val invalidatedRelay = CompletableDeferred<Unit>()
        var opened = 0
        val recovery = PairingReceiptRecovery(host, { _, _ -> fail("Enrolled path used") },
            StandardTestDispatcher(testScheduler), openRePair = { _, access, _ ->
                assertTrue(access.lease.isCurrent())
                if (++opened == 1) {
                    val relay = assertNotNull(host.borrowRecoveryRelay(access))
                    relayEntered.complete(relay)
                    RePairWire({
                        invalidatedRelay.await()
                        assertFalse(relay.lease.isCurrent())
                        throw java.io.IOException("Relay closed")
                    }, { host.releaseRecoveryRelay(access, relay) })
                } else {
                    assertNull(host.borrowRecoveryRelay(access))
                    RePairWire({ PairingRecoveryFrame.Expired(expiry(row, PairingExpiryReason.DEADLINE_ELAPSED)) })
                }
            }, clock = testScheduler.timeSource)
        val check = async { recovery.recover(id) }
        val relay = relayEntered.await()
        assertTrue(relay.lease.isCurrent())
        assertEquals(PairingReceiptOutcome.IN_PROGRESS, recovery.recover(id))
        val revision = open().use { it.snapshot().revision }
        host.remove(old.recordID, revision)
        assertFalse(relay.lease.isCurrent())
        invalidatedRelay.complete(Unit)
        assertEquals(PairingReceiptOutcome.RESOLVED, check.await())
        assertEquals(2, opened)
        assertEquals(EnrollmentPhase.REMOVED, open().use { store ->
            store.snapshot().entries.single { it.enrollment.recordID == id }.phase
        })
    }

    @Test fun directDiscoveryReservesHalfOfTheAttemptForRelay() {
        assertEquals(4_000L, recoveryDirectBudget(settingMillis = 10_000, attemptMillis = 8_000))
        assertEquals(1_500L, recoveryDirectBudget(settingMillis = 10_000, attemptMillis = 3_000))
        assertEquals(1_000L, recoveryDirectBudget(settingMillis = 1_000, attemptMillis = 8_000))
    }

    @Test fun recoveryAttemptStopsAtEightSecondsAndLastAttemptUsesTheRemainingBudget() = runTest {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val row = submittedRePair(host, keys)
        val budgets = mutableListOf<Long>()
        val times = mutableListOf<Long>()
        val slowJoins = mutableListOf<Long>()
        val recovery = PairingReceiptRecovery(host, { _, _ -> fail("Enrolled path used") },
            StandardTestDispatcher(testScheduler), openRePair = { _, _, budget ->
                budgets += budget
                times += testScheduler.currentTime
                RePairWire({ awaitCancellation() }, { if (budgets.size == 1) delay(8_000) })
            }, clock = testScheduler.timeSource, onSlowJoin = { slowJoins.add(it) })
        assertEquals(PairingReceiptOutcome.INCONCLUSIVE, recovery.recover(row.enrollment.recordID))
        assertEquals(listOf(8_000L, 8_000L, 3_000L), budgets)
        assertEquals(listOf(0L, 17_000L, 27_000L), times)
        assertEquals(listOf(8_000L), slowJoins)
        assertEquals(30_000L, testScheduler.currentTime)
        assertTrue(keys.retired.isEmpty())
    }

    @Test fun unsupportedExporterAndMissingRecoveryAlpnKeepTheCandidateIntact() = runTest {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val row = submittedRePair(host, keys)
        val snapshot = checkNotNull(storage.bytes).copyOf()
        var opened = 0
        val recovery = PairingReceiptRecovery(host, { _, _ -> fail("Legacy enrollment route cannot replace recovery") },
            StandardTestDispatcher(testScheduler), openRePair = { _, _, _ ->
                when (++opened) {
                    1 -> throw java.io.IOException("Unsupported SSL engine")
                    2 -> throw javax.net.ssl.SSLException("Missing exporter")
                    else -> throw javax.net.ssl.SSLException("Unexpected recovery ALPN")
                }
            }, clock = testScheduler.timeSource)
        assertEquals(PairingReceiptOutcome.INCONCLUSIVE, recovery.recover(row.enrollment.recordID))
        assertEquals(3, opened)
        assertTrue(keys.retirementAttempts.isEmpty())
        assertContentEquals(snapshot, storage.bytes)
    }

    @Test fun cleanupPreservesAPreparedOwnersAliasAndDifferentPublicKey() = runBlocking<Unit> {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val old = record(1)
        val row = submittedRePair(host, keys, old)
        val id = row.enrollment.recordID
        val basis = record(2)
        val shared = row.enrollment.transportKey
        val retained = PhoneEnrollment(basis.recordID.copyBytes(), basis.macID.copyBytes(), basis.accountID.copyBytes(),
            basis.phoneID.copyBytes(), basis.epoch.copyBytes(), basis.label, basis.authorityPublicKey.copyBytes(),
            basis.transportPublicKey.copyBytes(), shared, basis.decisionKey, basis.biometricKey, basis.enrollmentTag.copyBytes(), null)
        val before = open().use { it.snapshot().revision }
        host.remove(old.recordID, before)
        host.prepare(retained, transcript(retained), before + 1u, 1u)
        val changedAlias = row.enrollment.biometricKey.alias
        keys.publicKeys[changedAlias] = CborValue.Bytes(key().public.encoded.takeLast(65).toByteArray())
        val access = host.recoverable(id)
        host.retireExpiredRePair(access, expiry(row)) {}
        host.release(id, access.lease)
        host.reconcileRePairOnStartup()
        assertTrue(shared.alias in keys.allocated)
        assertFalse(shared.alias in keys.retirementAttempts)
        assertTrue(changedAlias in keys.allocated)
        assertTrue(changedAlias in keys.retirementAttempts)
        assertEquals(listOf(row.enrollment.decisionKey.alias), keys.retired)
    }

    @Test fun archiveRejectsAReservationThatAliasesARetiredCandidateKey() = runBlocking<Unit> {
        val keys = RePairKeys()
        val host = rePairHost(keys)
        val row = submittedRePair(host, keys)
        val candidateID = row.enrollment.recordID
        val access = host.recoverable(candidateID)
        host.retireExpiredRePair(access, expiry(row)) {}
        host.release(candidateID, access.lease)
        val other = record(6, mac = 32)
        val revision = open().use { it.snapshot().revision }
        val transcript = transcript(other)
        host.prepare(other, transcript, revision, 1u)
        host.activate(other.recordID, receipt(transcript))
        val keyIDs = listOf(row.enrollment.transportKey.keyID, CborValue.Bytes(id(200)), CborValue.Bytes(id(201)))
        val before = checkNotNull(storage.bytes).copyOf()
        assertFails { host.reserveRePair(envelope(other), id(90), id(91), keyIDs) }
        assertContentEquals(before, storage.bytes)
        assertTrue(open().use { it.snapshot().rePairReservations }.isEmpty())
    }

    @Test fun recoveryActivatesOnlyTheRetainedTranscriptAndPreservesKeys() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val wire = RecoveryWire({ receipt(t).copyBytes() })
        val recovery = PairingReceiptRecovery(h, { _, row ->
            assertEquals(e.recordID, row.enrollment.recordID)
            assertContentEquals(t.encode(), checkNotNull(row.pairing).transcript.encode())
            wire
        }, Dispatchers.Unconfined)
        assertEquals(PairingReceiptOutcome.RESOLVED, recovery.recover(e.recordID))
        assertEquals(1, wire.queries); assertEquals(1, wire.joins)
        open().use {
            val active = it.snapshot().entries.single()
            assertEquals(EnrollmentPhase.ACTIVE, active.phase)
            assertEquals(e.transportKey.alias, active.enrollment.transportKey.alias)
            assertEquals(e.biometricKey.publicKey, active.enrollment.biometricKey.publicKey)
        }
    }

    @Test fun unavailableReceiptKeepsThePreparationAndReleasesLeaseAfterIoJoins() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        val prepared = h.prepare(e, t, 0u, 1u).entries.single()
        var retired = false
        val wire = RecoveryWire({ null }, {
            assertFails { h.abandonUnsubmitted(prepared) { retired = true } }
            assertFalse(retired)
        })
        assertEquals(PairingReceiptOutcome.INCONCLUSIVE, PairingReceiptRecovery(h, { _, _ -> wire }, Dispatchers.Unconfined).recover(e.recordID))
        open().use { assertEquals(1uL, it.snapshot().revision); assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
        assertEquals(1, wire.queries); assertEquals(1, wire.joins)
        // This fixture's original setup never submitted a proof. The recovery borrow must now be gone.
        h.abandonUnsubmitted(prepared) { retired = true }
        assertTrue(retired)
    }

    @Test fun invalidRecoveryReceiptCannotActivateOrRemovePreparation() = runBlocking<Unit> {
        failedRecoveryPreservesPreparation(networkFailure = false)
    }

    @Test fun recoveryNetworkFailureCannotActivateOrRemovePreparation() = runBlocking<Unit> {
        failedRecoveryPreservesPreparation(networkFailure = true)
    }

    private suspend fun failedRecoveryPreservesPreparation(networkFailure: Boolean) {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val wire = RecoveryWire({ if (networkFailure) error("Synthetic network failure") else ByteArray(64) })
        assertFails { PairingReceiptRecovery(h, { _, _ -> wire }, Dispatchers.Unconfined).recover(e.recordID) }
        assertEquals(1, wire.joins)
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
        assertTrue(invalidated.isEmpty())
    }

    @Test fun recoveryCancellationJoinsIoAndKeepsAllPreparedKeys() = runBlocking<Unit> {
        val h = host(); val e = record(1); h.prepare(e, transcript(e), 0u, 1u)
        val started = CompletableDeferred<Unit>()
        val wire = RecoveryWire({ started.complete(Unit); CompletableDeferred<ByteArray?>().await() })
        val operation = async { PairingReceiptRecovery(h, { _, _ -> wire }, Dispatchers.Unconfined).recover(e.recordID) }
        started.await(); operation.cancel(); operation.join()
        assertEquals(1, wire.joins)
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
        assertTrue(invalidated.isEmpty())
    }

    @Test fun localRemovalDuringConnectionStopsRecoveryBeforeAnyQuery() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e); h.prepare(e, t, 0u, 1u)
        val wire = RecoveryWire({ receipt(t).copyBytes() })
        val recovery = PairingReceiptRecovery(h, { _, _ -> h.remove(e.recordID, 1u); wire }, Dispatchers.Unconfined)
        assertFails { recovery.recover(e.recordID) }
        assertEquals(0, wire.queries); assertEquals(1, wire.joins)
        open().use { assertEquals(EnrollmentPhase.REMOVED, it.snapshot().entries.single().phase) }
    }

    @Test fun activationWriteFailureKeepsTheSamePreparationForReceiptRetry() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e); h.prepare(e, t, 0u, 1u)
        val first = RecoveryWire({ storage.fail = true; receipt(t).copyBytes() })
        assertFails { PairingReceiptRecovery(h, { _, _ -> first }, Dispatchers.Unconfined).recover(e.recordID) }
        assertEquals(1, first.joins)
        storage.fail = false
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
        val retry = RecoveryWire({ receipt(t).copyBytes() })
        assertEquals(PairingReceiptOutcome.RESOLVED, PairingReceiptRecovery(h, { _, _ -> retry }, Dispatchers.Unconfined).recover(e.recordID))
        assertEquals(1, retry.joins)
    }

    @Test fun receiptNetworkDeadlineCannotCancelAStartedActivation() = runTest {
        val h = host(); val e = record(1); val t = transcript(e); h.prepare(e, t, 0u, 1u)
        val wire = RecoveryWire({ receipt(t).copyBytes() })
        var observed: EnrollmentPhase? = null
        storage.beforeReplace = {
            testScheduler.advanceTimeBy(30_001)
            testScheduler.runCurrent()
        }
        val recovery = PairingReceiptRecovery(h, { _, _ -> wire }, StandardTestDispatcher(testScheduler))
        assertEquals(PairingReceiptOutcome.RESOLVED, recovery.checkAndReconcile(e.recordID) {
            open().use { observed = it.snapshot().entries.single().phase }
        })
        assertEquals(EnrollmentPhase.ACTIVE, observed)
        assertEquals(1, wire.joins)
    }

    @Test fun callerCancellationDuringCommitStillRefreshesTheCommittedInventory() = runTest {
        val h = host(); val e = record(1); val t = transcript(e); h.prepare(e, t, 0u, 1u)
        val wire = RecoveryWire({ receipt(t).copyBytes() })
        var observed: EnrollmentPhase? = null
        val operation = async {
            val caller = checkNotNull(currentCoroutineContext()[Job])
            storage.beforeReplace = { caller.cancel() }
            PairingReceiptRecovery(h, { _, _ -> wire }, StandardTestDispatcher(testScheduler))
                .checkAndReconcile(e.recordID) { open().use { observed = it.snapshot().entries.single().phase } }
        }
        operation.join()
        assertTrue(operation.isCancelled)
        assertEquals(EnrollmentPhase.ACTIVE, observed)
        assertEquals(1, wire.joins)
    }

    @Test fun cancellationBeforeActivationKeepsThePreparedInventory() = runTest {
        val h = host(); val e = record(1); val t = transcript(e); h.prepare(e, t, 0u, 1u)
        var observed: EnrollmentPhase? = null
        val wire = RecoveryWire({ currentCoroutineContext().cancel(); receipt(t).copyBytes() })
        val operation = async {
            PairingReceiptRecovery(h, { _, _ -> wire }, StandardTestDispatcher(testScheduler))
                .checkAndReconcile(e.recordID) { open().use { observed = it.snapshot().entries.single().phase } }
        }
        operation.join()
        assertTrue(operation.isCancelled)
        assertEquals(EnrollmentPhase.PREPARED, observed)
        assertEquals(1, wire.joins)
        assertTrue(invalidated.isEmpty())
    }

    @Test fun cancellationWhileAcquiringPreparationCannotLeakItsLease() = runTest {
        val h = host(); val e = record(1); val t = transcript(e)
        val prepared = h.prepare(e, t, 0u, 1u).entries.single()
        var opened = false
        val operation = async {
            val caller = checkNotNull(currentCoroutineContext()[Job])
            afterCustodyCheck = { caller.cancel() }
            PairingReceiptRecovery(h, { _, _ ->
                opened = true
                RecoveryWire({ receipt(t).copyBytes() })
            }, StandardTestDispatcher(testScheduler)).recover(e.recordID)
        }
        operation.join()
        afterCustodyCheck = {}
        assertTrue(operation.isCancelled); assertFalse(opened)
        var retired = false
        h.abandonUnsubmitted(prepared) { retired = true }
        assertTrue(retired)
    }

    @Test fun activationReopensRetainedAttemptAndInvalidatesBeforeCommit() = runBlocking<Unit> {
        val e = record(1); val t = transcript(e)
        host().prepare(e, t, 0u, 1u)
        assertTrue(invalidated.isEmpty())
        val result = host { ids ->
            assertEquals(setOf(e.recordID), ids)
            open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
        }.activate(e.recordID, receipt(t))
        assertEquals(EnrollmentPhase.ACTIVE, result.entries.single().phase)
        assertFails { host().activate(e.recordID, receipt(t)) }
    }

    @Test fun replacementClosesBothIncarnationsBeforeChangingTrust() = runBlocking<Unit> {
        val old = record(1); val original = transcript(old)
        host().prepare(old, original, 0u, 1u)
        val active = host().activate(old.recordID, receipt(original))
        val next = record(2); val replacement = transcript(next, old)
        host().prepare(next, replacement, active.revision, 1u, old.recordID)
        val result = host { ids ->
            assertEquals(setOf(old.recordID, next.recordID), ids)
            open().use { store ->
                assertEquals(EnrollmentPhase.ACTIVE, store.snapshot().entries.single { it.enrollment.recordID == old.recordID }.phase)
                assertEquals(EnrollmentPhase.PREPARED, store.snapshot().entries.single { it.enrollment.recordID == next.recordID }.phase)
            }
        }.activate(next.recordID, receipt(replacement))
        assertEquals(EnrollmentPhase.REMOVED, result.entries.single { it.enrollment.recordID == old.recordID }.phase)
        assertEquals(EnrollmentPhase.ACTIVE, result.entries.single { it.enrollment.recordID == next.recordID }.phase)
    }

    @Test fun localRemovalRefusesToStrandAnOrdinaryPreparedReplacement() = runBlocking {
        val host = host()
        val previous = record(1)
        activatePredecessor(host, previous)
        val next = record(2)
        val replacement = transcript(next, previous)
        val prepared = host.prepare(next, replacement, 2u, 1u, previous.recordID)
        val access = host.prepared(next.recordID, replacement)
        invalidated.clear()
        try {
            assertFailsWith<OrdinaryPairingReplacementPending> {
                host.remove(previous.recordID, prepared.revision)
            }
            assertTrue(access.lease.isCurrent())
            assertTrue(invalidated.isEmpty())
            open().use { store ->
                val retained = store.snapshot()
                assertEquals(prepared.revision, retained.revision)
                assertEquals(EnrollmentPhase.ACTIVE, retained.entries.single { it.enrollment.recordID == previous.recordID }.phase)
                assertEquals(EnrollmentPhase.PREPARED, retained.entries.single { it.enrollment.recordID == next.recordID }.phase)
            }

            val cancelled = host.remove(next.recordID, prepared.revision)
            assertFalse(access.lease.isCurrent())
            val removed = host.remove(previous.recordID, cancelled.revision)
            assertTrue(removed.entries.all { it.phase == EnrollmentPhase.REMOVED })
        } finally {
            host.release(next.recordID, access.lease)
        }
    }

    @Test fun custodyFailurePreventsPreparationAndActivationWithoutClosingConnections() = runBlocking<Unit> {
        val e = record(1); val t = transcript(e)
        custodyAvailable = false
        assertFails { host().prepare(e, t, 0u, 1u) }
        open().use { assertTrue(it.snapshot().entries.isEmpty()) }
        custodyAvailable = true
        host().prepare(e, t, 0u, 1u)
        custodyAvailable = false
        assertFails { host().activate(e.recordID, receipt(t)) }
        assertTrue(invalidated.isEmpty())
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
        assertEquals(3, custodyChecks)
        host().remove(e.recordID, 1u)
        assertEquals(3, custodyChecks)
    }

    @Test fun invalidReceiptDoesNotInterruptConnections() = runBlocking<Unit> {
        val e = record(1); host().prepare(e, transcript(e), 0u, 1u)
        assertFails { host().activate(e.recordID, CborValue.Bytes(ByteArray(64))) }
        assertTrue(invalidated.isEmpty())
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
    }

    @Test fun invalidationFailurePreventsActivationAndRemoval() = runBlocking<Unit> {
        val e = record(1); val t = transcript(e); host().prepare(e, t, 0u, 1u)
        val broken = host { error("Synthetic close failure") }
        assertFails { broken.activate(e.recordID, receipt(t)) }
        assertFails { broken.remove(e.recordID, 1u) }
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
    }

    @Test fun removalRejectsStaleRevisionAndLateReceipt() = runBlocking<Unit> {
        val e = record(1); val t = transcript(e); host().prepare(e, t, 0u, 1u)
        assertFails { host().remove(e.recordID, 0u) }
        assertTrue(invalidated.isEmpty())
        host().remove(e.recordID, 1u)
        assertEquals(listOf(setOf(e.recordID)), invalidated)
        assertFails { host().activate(e.recordID, receipt(t)) }
        open().use { assertEquals(EnrollmentPhase.REMOVED, it.snapshot().entries.single().phase) }
    }
    @Test fun preparedLeaseRetiresBeforeRemovalAndCannotLoadAnAlteredTranscript() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val access = h.prepared(e.recordID, t)
        assertTrue(access.lease.isCurrent())
        assertFails { h.prepared(e.recordID, transcript(record(2))) }
        h.remove(e.recordID, 1u)
        assertFalse(access.lease.isCurrent())
        assertFails { h.prepared(e.recordID, t) }
    }

    @Test fun verifiedActivationRetiresItsPreparedBiometricLease() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val access = h.prepared(e.recordID, t)
        h.activate(e.recordID, receipt(t))
        assertFalse(access.lease.isCurrent())
        assertFails { h.prepared(e.recordID, t) }
    }

    @Test fun releasingOnePreparedLeaseDoesNotRetireAnother() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val first = h.prepared(e.recordID, t); val second = h.prepared(e.recordID, t)
        h.release(e.recordID, first.lease)
        assertFalse(first.lease.isCurrent()); assertTrue(second.lease.isCurrent())
        h.release(e.recordID, second.lease)
        assertFalse(second.lease.isCurrent())
    }

    private fun expected(e: PhoneEnrollment, t: PairingTranscript) =
        StoredPhoneEnrollment(e, EnrollmentPhase.PREPARED, PreparedPairing(t, null, 1u))

    @Test fun abandonedUnsubmittedSetupCommitsRemovalBeforeKeyRetirementAndPreservesOtherMacs() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val access = h.prepared(e.recordID, t)
        h.release(e.recordID, access.lease)
        val other = record(2, mac = 22)
        h.prepare(other, transcript(other), 1u, 1u)
        var retired = false
        h.abandonUnsubmitted(expected(e, t)) {
            assertTrue(mutex.isLocked)
            open().use { store ->
                assertEquals(EnrollmentPhase.REMOVED, store.snapshot().entries.single { it.enrollment.recordID == e.recordID }.phase)
                assertEquals(EnrollmentPhase.PREPARED, store.snapshot().entries.single { it.enrollment.recordID == other.recordID }.phase)
            }
            retired = true
        }
        assertTrue(retired)
        assertEquals(listOf(setOf(e.recordID)), invalidated)
        assertFalse(access.lease.isCurrent())
        assertFails { h.activate(e.recordID, receipt(t)) }
        val retry = record(3)
        open().use { store -> h.prepare(retry, transcript(retry), store.snapshot().revision, 1u) }
    }

    @Test fun abandonedSetupRefusesActiveOrChangedRecordsBeforeInvalidationAndKeyRetirement() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val altered = record(1)
        assertFails { h.abandonUnsubmitted(expected(altered, transcript(altered))) { fail("Changed keys must survive") } }
        assertTrue(invalidated.isEmpty())
        h.activate(e.recordID, receipt(t)); invalidated.clear()
        assertFails { h.abandonUnsubmitted(expected(e, t)) { fail("Active pairing must survive") } }
        assertTrue(invalidated.isEmpty())
        open().use { assertEquals(EnrollmentPhase.ACTIVE, it.snapshot().entries.single().phase) }
    }

    @Test fun abandonmentRequiresEveryOtherPreparedBorrowerToFinish() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val first = h.prepared(e.recordID, t); val second = h.prepared(e.recordID, t)
        h.release(e.recordID, first.lease)
        assertFails { h.abandonUnsubmitted(expected(e, t)) { fail("Another borrower can still be using its keys") } }
        assertTrue(invalidated.isEmpty()); assertTrue(second.lease.isCurrent())
        h.release(e.recordID, second.lease)
        h.abandonUnsubmitted(expected(e, t)) { }
    }

    @Test fun abandonmentPreservesKeysOnInvalidationOrStorageFailure() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        assertFails { host { error("Synthetic close failure") }.abandonUnsubmitted(expected(e, t)) { fail("Do not retire keys") } }
        storage.fail = true
        assertFails { h.abandonUnsubmitted(expected(e, t)) { fail("Unconfirmed removal must keep keys") } }
        storage.fail = false
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
    }

    @Test fun confirmedRemovalCanRetryKeyRetirementWithoutAnotherArchiveWrite() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        assertFails { h.abandonUnsubmitted(expected(e, t)) { error("Synthetic key failure") } }
        val revision = open().use { store ->
            assertEquals(EnrollmentPhase.REMOVED, store.snapshot().entries.single().phase)
            store.snapshot().revision
        }
        storage.fail = true
        var retired = false
        h.abandonUnsubmitted(expected(e, t)) { retired = true }
        assertTrue(retired)
        open().use { assertEquals(revision, it.snapshot().revision) }
    }

    @Test fun healthyArchiveWithoutTheUnsubmittedRowAllowsOnlyOwnedKeyRetirement() = runBlocking<Unit> {
        val e = record(1); val t = transcript(e)
        var retired = false
        host().abandonUnsubmitted(expected(e, t)) { assertTrue(mutex.isLocked); retired = true }
        assertTrue(retired)
        open().use { assertEquals(0uL, it.snapshot().revision); assertTrue(it.snapshot().entries.isEmpty()) }
        val unavailable = StoredPairingHost({ error("Never create during cleanup") }, { null }, mutex, {}, {}, Dispatchers.Unconfined)
        assertFails { unavailable.abandonUnsubmitted(expected(e, t)) { fail("Unknown archive must keep keys") } }
    }

    @Test fun anotherRecordReferencingTheKeysPreventsRetirementEvenAfterLocalRemoval() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u); h.remove(e.recordID, 1u); invalidated.clear()
        val other = record(2)
        val reused = PhoneEnrollment(other.recordID.copyBytes(), other.macID.copyBytes(), other.accountID.copyBytes(),
            other.phoneID.copyBytes(), other.epoch.copyBytes(), other.label, other.authorityPublicKey.copyBytes(),
            other.transportPublicKey.copyBytes(), e.transportKey, e.decisionKey, e.biometricKey, other.enrollmentTag.copyBytes(), null)
        h.prepare(reused, transcript(reused), 2u, 1u)
        assertFails { h.abandonUnsubmitted(expected(e, t)) { fail("Referenced keys must survive") } }
        assertTrue(invalidated.isEmpty())
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single { it.enrollment.recordID == reused.recordID }.phase) }
    }

    @Test fun preparedLeasesAreBoundedAndReleasedCapacityCanBeReused() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val leases = (1..32).map { h.prepared(e.recordID, t).lease }
        assertFails { h.prepared(e.recordID, t) }
        h.release(e.recordID, leases.first())
        assertTrue(h.prepared(e.recordID, t).lease.isCurrent())
        h.remove(e.recordID, 1u)
        assertTrue(leases.none { it.isCurrent() })
    }
    private fun notifyingHost(changed: () -> Unit) = StoredPairingHost(
        ::open, ::open, mutex, { assertTrue(mutex.isLocked); invalidated.add(it) },
        { custodyChecks++; check(custodyAvailable) }, Dispatchers.Unconfined, onChanged = changed,
    )

    @Test fun registrationSchedulingSeesCommittedTrustOutsideTheEnrollmentLock() = runBlocking<Unit> {
        val phases = mutableListOf<EnrollmentPhase>()
        val h = notifyingHost {
            assertTrue(mutex.tryLock()); mutex.unlock()
            open().use { phases += it.snapshot().entries.single().phase }
        }
        val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u); assertTrue(phases.isEmpty())
        val active = h.activate(e.recordID, receipt(t))
        assertEquals(listOf(EnrollmentPhase.ACTIVE), phases)
        h.remove(e.recordID, active.revision)
        assertEquals(listOf(EnrollmentPhase.ACTIVE, EnrollmentPhase.REMOVED), phases)
    }

    @Test fun failedTrustWritesNeverScheduleRegistration() = runBlocking<Unit> {
        var changes = 0
        val h = notifyingHost { changes++ }; val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u); storage.fail = true
        assertFails { h.activate(e.recordID, receipt(t)) }; assertEquals(0, changes)
        storage.fail = false
        val active = h.activate(e.recordID, receipt(t)); assertEquals(1, changes)
        storage.fail = true
        assertFails { h.remove(e.recordID, active.revision) }; assertEquals(1, changes)
        storage.fail = false
        open().use { assertEquals(EnrollmentPhase.ACTIVE, it.snapshot().entries.single().phase) }
    }

    @Test fun schedulingFailureCannotUndoACommittedPairingOrRemoval() = runBlocking<Unit> {
        var changes = 0
        val h = notifyingHost { changes++; error("Synthetic scheduling failure") }
        val e = record(1); val t = transcript(e); h.prepare(e, t, 0u, 1u)
        val active = h.activate(e.recordID, receipt(t))
        assertEquals(EnrollmentPhase.ACTIVE, active.entries.single().phase)
        val removed = h.remove(e.recordID, active.revision)
        assertEquals(EnrollmentPhase.REMOVED, removed.entries.single().phase)
        assertEquals(2, changes)
        open().use { assertEquals(EnrollmentPhase.REMOVED, it.snapshot().entries.single().phase) }
    }

}
