package dev.remozio.phone.updates

import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import org.junit.Test
import kotlin.test.*

class PhoneUpdateSchedulingChallengeTest {
    private val controlLimits = CborLimits(1024, 2, 32)
    private val responseLimits = CborLimits(2048, 2, 32)
    private val signingLimits = CborLimits(4096, 2, 32)
    private fun id(n: Int, size: Int = 16) = ByteArray(size) { n.toByte() }
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun sign(key: KeyPair, input: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(key.private); update(input); sign()
    }
    private inner class Fixture {
        val root = pair(); val decision = pair(); val biometric = pair()
        var nanos = 1_000_000L
        var clockFails = false
        val update = id(9, 32)
        fun reference(role: EnrollmentKeyRole, key: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) key.public.encoded else key.public.encoded.takeLast(65).toByteArray())
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(1), id(2), id(3), id(4), id(5), "Synthetic update host",
            root.public.encoded.takeLast(65).toByteArray(), pair().public.encoded,
            reference(EnrollmentKeyRole.TRANSPORT, pair()), reference(EnrollmentKeyRole.DECISION, decision),
            reference(EnrollmentKeyRole.BIOMETRIC, biometric), id(6, 32), null), EnrollmentPhase.ACTIVE)
        fun query(action: UpdateSchedulingAction = UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES,
                  now: () -> Long = { if (clockFails) error("Synthetic clock failure") else nanos },
                  nonce: () -> ByteArray = { id(30, 32) }) =
            PhoneUpdateSchedulingQuery.begin(record, update, 7u, 8u, action, now, 5000, nonce)
        fun control(action: UpdateSchedulingAction = UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES,
                    mac: ByteArray = id(2), account: ByteArray = id(3), phone: ByteArray = id(4), epoch: ByteArray = id(5),
                    keyID: ByteArray = record.enrollment.decisionKey.keyID.copyBytes(), update: ByteArray = this.update,
                    generation: ULong = 7u, revision: ULong = 8u, issued: ULong = 1_000u, expires: ULong = 31_000u) =
            UpdateSchedulingControl(mac, account, phone, epoch, id(20), id(21, 32), keyID, update,
                generation, revision, issued, expires, action).encode(controlLimits)
        fun response(query: PhoneUpdateSchedulingQuery, control: ByteArray = control(), nonce: ByteArray = query.queryNonce,
                     signer: KeyPair = root): Pair<ByteArray, ByteArray> {
            val body = RootUpdateSchedulingChallenge(nonce, control, controlLimits).encode(responseLimits)
            return body to sign(signer, RootUpdateSchedulingChallengeSigningInput.make(1u, body, responseLimits, signingLimits))
        }
        fun verified(query: PhoneUpdateSchedulingQuery = query(), control: ByteArray = control()): PhoneUpdateSchedulingChallenge {
            val (body, signature) = response(query, control)
            return query.verify(record, body, signature)
        }
    }

    @Test fun eachExplicitActionSignsOnlyTheExactVerifiedControlOnce() {
        for (action in UpdateSchedulingAction.entries) {
            val f = Fixture(); val q = f.query(action); val control = f.control(action); val (body, rootSignature) = f.response(q, control)
            val challenge = q.verify(f.record, body, rootSignature)
            q.close(); q.close()
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { q.verify(f.record, body, rootSignature) }
            val signature = challenge.sign(f.record) { sign(f.decision, it) }
            assertTrue(UpdateSchedulingSignature.verify(signature, f.record.enrollment.decisionKey.publicKey.copyBytes(),
                1u, control, controlLimits, signingLimits))
            assertContentEquals(control, challenge.bytes(f.record))
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { challenge.sign(f.record) { error("Must not sign twice") } }
            val changed = challenge.bytes(f.record); changed.fill(0)
            assertContentEquals(control, challenge.bytes(f.record))
        }
    }

    @Test fun rootQueryScopeKeyUpdateGenerationRevisionAndActionMustMatch() {
        val f = Fixture()
        val controls = listOf(f.control(mac = id(99)), f.control(account = id(99)), f.control(phone = id(99)),
            f.control(epoch = id(99)), f.control(keyID = f.record.enrollment.biometricKey.keyID.copyBytes()),
            f.control(update = id(99, 32)), f.control(generation = 9u), f.control(revision = 9u),
            f.control(action = UpdateSchedulingAction.DEFER_UPDATE))
        for (control in controls) {
            val q = f.query(); val (body, signature) = f.response(q, control)
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { q.verify(f.record, body, signature) }
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { f.verified(q) }
        }
        for (wrongNonce in listOf(false, true)) {
            val q = f.query(); val (body, signature) = f.response(q,
                nonce = if (wrongNonce) id(99, 32) else q.queryNonce, signer = if (wrongNonce) f.root else pair())
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { q.verify(f.record, body, signature) }
        }
    }

    @Test fun untrustedPayloadBoundsAndWrongSignaturePurposeCannotCreateAChallenge() {
        val f = Fixture()
        for (mode in 0..4) {
            val q = f.query(); val (body, signature) = f.response(q)
            val invalid = when (mode) { 0 -> ByteArray(2049); 1 -> byteArrayOf(0xa0.toByte()); else -> body }
            val proof = when (mode) {
                2 -> ByteArray(63)
                3 -> sign(f.decision, UpdateSchedulingSigningInput.make(1u, f.control(), controlLimits, signingLimits))
                4 -> signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
                else -> signature
            }
            assertEquals("Update scheduling unavailable", assertFailsWith<PhoneUpdateSchedulingUnavailable> {
                q.verify(f.record, invalid, proof)
            }.message)
        }
    }

    @Test fun inactiveReplacedAndChangedEnrollmentStopBeforeDecisionSigning() {
        val f = Fixture(); val other = Fixture()
        val records = listOf(StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED),
            StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.REMOVED), other.record)
        for (current in records) {
            val q = f.query(); val (body, signature) = f.response(q)
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { q.verify(current, body, signature) }
            val challenge = f.verified()
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { challenge.sign(current) { error("Must not use a stale identity") } }
        }
    }

    @Test fun originalQueryTimeIncludesNonceGenerationAndResponseDelay() {
        val f = Fixture()
        assertFails { f.query(nonce = { f.nanos += 5_000_000_000L; id(30, 32) }) }
        val q = f.query(); val (body, signature) = f.response(q); f.nanos += 5_000_000_000L
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { q.verify(f.record, body, signature) }
        val delayed = f.query(); val short = f.control(expires = 1005u); val reply = f.response(delayed, short)
        f.nanos += 5_000_000L
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { delayed.verify(f.record, reply.first, reply.second) }
    }

    @Test fun sleepExactExpiryAndFractionalAgeCannotRenewTheChallenge() {
        for (elapsed in listOf(5_000_000L, 4_000_001L, 30_000_000_000L)) {
            val f = Fixture(); val challenge = f.verified(control = f.control(expires = 1005u)); f.nanos += elapsed
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { challenge.sign(f.record) { error("Expired challenge reached the signer") } }
        }
        val f = Fixture(); val challenge = f.verified(control = f.control(expires = 1005u)); f.nanos += 4_000_000L
        challenge.sign(f.record) { sign(f.decision, it) }
        f.nanos += 1_000_000L
        assertFails { challenge.bytes(f.record) }
    }

    @Test fun regressionAndClockFailurePermanentlyRetireTheChallenge() {
        for (fail in listOf(false, true)) {
            val f = Fixture(); val challenge = f.verified(); f.nanos += 10_000_000L
            challenge.sign(f.record) { sign(f.decision, it) }
            if (fail) f.clockFails = true else f.nanos -= 1_000_000L
            assertFails { challenge.bytes(f.record) }
            f.clockFails = false; f.nanos += 20_000_000L
            assertFails { challenge.bytes(f.record) }
        }
    }

    @Test fun elapsedTimeAndClosureDuringSigningPreventASignatureFromEscaping() {
        for (close in listOf(false, true)) {
            val f = Fixture(); val challenge = f.verified()
            assertFailsWith<PhoneUpdateSchedulingUnavailable> {
                challenge.sign(f.record) { input ->
                    val signature = sign(f.decision, input)
                    if (close) challenge.close() else f.nanos += 30_000_000_000L
                    signature
                }
            }
            assertFails { challenge.bytes(f.record) }
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { challenge.sign(f.record) { error("Must not retry") } }
        }
    }

    @Test fun closureBeforeSigningCompletionWinsEvenWhenTheFinalClockReadIsInProgress() {
        val f = Fixture(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        var signing = false; var reads = 0
        val q = f.query(now = {
            if (signing && ++reads == 3) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
            }
            f.nanos
        })
        val challenge = f.verified(q); signing = true
        val executor = Executors.newSingleThreadExecutor()
        val closer = Thread { challenge.close() }
        try {
            val result = executor.submit<ByteArray> { challenge.sign(f.record) { sign(f.decision, it) } }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            closer.start()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (closer.state != Thread.State.BLOCKED && System.nanoTime() < deadline) Thread.yield()
            assertEquals(Thread.State.BLOCKED, closer.state)
            release.countDown()
            assertIs<PhoneUpdateSchedulingUnavailable>(assertFailsWith<ExecutionException> {
                result.get(5, TimeUnit.SECONDS)
            }.cause)
            closer.join(5000); assertFalse(closer.isAlive)
            assertFails { challenge.bytes(f.record) }
        } finally {
            release.countDown(); closer.join(5000); executor.shutdownNow()
        }
    }

    @Test fun wrongBiometricKeyInvalidSignatureAndSignerFailureConsumeTheAttempt() {
        for (mode in 0..3) {
            val f = Fixture(); val challenge = f.verified()
            assertFailsWith<PhoneUpdateSchedulingUnavailable> {
                challenge.sign(f.record) { when (mode) {
                    0 -> sign(f.biometric, it)
                    1 -> ByteArray(65)
                    2 -> ByteArray(64)
                    else -> error("Synthetic signing failure")
                } }
            }
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { challenge.sign(f.record) { error("Must not retry") } }
            assertFails { challenge.bytes(f.record) }
        }
    }

    @Test fun closureAndInvalidClockOrLifetimeFailClosed() {
        val f = Fixture(); val q = f.query(); q.close(); q.close()
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { f.verified(q) }
        val challenge = f.verified(); challenge.close(); challenge.close()
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { challenge.sign(f.record) { error("Closed challenge reached signer") } }
        assertFails { f.query(now = { -1 }) }
        val huge = f.control(issued = 1u, expires = ULong.MAX_VALUE)
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { f.verified(control = huge) }
        assertFails { f.query(nonce = { ByteArray(31) }) }
    }

    @Test fun queryCopiesSelectionAndNonceWithoutExposingState() {
        val f = Fixture(); val nonce = id(30, 32); val q = f.query(nonce = { nonce })
        nonce.fill(0); q.queryNonce.fill(0); val original = f.update.copyOf(); f.update.fill(99)
        val challenge = f.verified(q, f.control(update = original))
        val signature = challenge.sign(f.record) { sign(f.decision, it) }
        assertEquals(64, signature.size)
        assertEquals("PhoneUpdateSchedulingQuery(redacted)", q.toString())
        assertEquals("PhoneUpdateSchedulingChallenge(redacted)", challenge.toString())
    }

    @Test fun concurrentVerificationTransfersOnlyOneOwnerWithoutRetiringTheWinner() {
        val f = Fixture(); val q = f.query(); val reply = f.response(q); val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val futures = (1..2).map { pool.submit<PhoneUpdateSchedulingChallenge?> {
                assertTrue(start.await(5, TimeUnit.SECONDS))
                try { q.verify(f.record, reply.first, reply.second) } catch (_: PhoneUpdateSchedulingUnavailable) { null }
            } }
            start.countDown(); val results = futures.map { it.get(5, TimeUnit.SECONDS) }
            val winner = results.filterNotNull().single()
            winner.sign(f.record) { sign(f.decision, it) }
        } finally { pool.shutdownNow() }
    }
}
