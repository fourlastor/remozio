package dev.remozio.android.enrollment

import android.content.Context
import dev.remozio.android.biometrics.AndroidBiometricKeyCreation
import dev.remozio.android.biometrics.AndroidPairingBiometrics
import dev.remozio.android.decisions.AndroidDecisionKeyCreation
import dev.remozio.android.requests.RequestElapsedClock
import dev.remozio.android.requests.commandInspectionCapabilities
import dev.remozio.android.transport.AndroidTransportKeyCreation
import dev.remozio.android.transport.CreatedTransportIdentity
import dev.remozio.android.transport.LocalNetworkSettings
import dev.remozio.android.transport.androidPairingRoutes
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.PairingSetupChannel
import dev.remozio.protocol.*
import java.security.KeyStore
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.*
import dev.remozio.phone.transport.authenticatePairingRoutes
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** One explicit setup owner. No network input can select a retained record or activate it without its Root receipt. */
internal class AndroidPairingAttempt(
    context: Context,
    parent: CoroutineScope,
    private val store: StoredPairingHost,
) : AutoCloseable {
    private val app = context.applicationContext
    private val job = SupervisorJob(requireNotNull(parent.coroutineContext[Job]))
    private val scope = CoroutineScope(job + Dispatchers.IO)
    private val closed = AtomicBoolean(false)
    private val operations = Mutex()
    private val ownedKeys = mutableListOf<EnrollmentKeyReference>()
    private var identity: CreatedTransportIdentity? = null
    private var channel: PairingSetupChannel? = null
    private var invitation: PairingInvitation? = null
    private var transportKey: EnrollmentKeyReference? = null
    private var decisionKey: EnrollmentKeyReference? = null
    private var biometricKey: EnrollmentKeyReference? = null
    private var expectedRevision: ULong? = null
    private var enrollment: PhoneEnrollment? = null
    private var prepared = false
    private var preparedAccess: PreparedPairingAccess? = null
    private var biometric: AndroidPairingBiometrics? = null
    private var proofSubmitted = false
    private val phoneID = randomID()
    private val epoch = randomID()
    val phoneSuffix: String = phoneID.takeLast(4).joinToString("") { "%02X".format(it.toInt() and 255) }
    val transcript: PairingTranscript get() = checkNotNull(channel).transcript

    suspend fun connect(text: String): PairingTranscript = operation {
        check(invitation == null)
        val selected = PairingInvitation.importText(text.trim())
        val snapshot = store.setupSnapshot()
        require(snapshot.entries.size < 1024)
        require(snapshot.entries.none { it.phase != EnrollmentPhase.REMOVED &&
            it.enrollment.macID == selected.macID && it.enrollment.accountID == selected.accountID })
        invitation = selected; expectedRevision = snapshot.revision
        // Provider calls cannot be interrupted safely. Retain each successful reference before cancellation can resume.
        withContext(NonCancellable + Dispatchers.IO) {
            active()
            val now = Instant.now()
            val made = AndroidTransportKeyCreation.create(app, now.minusSeconds(300), now.plusSeconds(31_536_000))
            identity = made
            val transport = EnrollmentKeyReference(EnrollmentKeyRole.TRANSPORT, randomID(), made.alias, made.publicKey())
            transportKey = transport; ownedKeys.add(transport)
            active()
            val decision = AndroidDecisionKeyCreation.create(app)
            decisionKey = decision; ownedKeys.add(decision)
            active()
            val bio = AndroidBiometricKeyCreation.create(app)
            biometricKey = bio; ownedKeys.add(bio)
        }
        active()
        val offer = ChannelOffer(ChannelRole.PHONE,
            ChannelScope(selected.macID.copyBytes(), selected.accountID.copyBytes(), phoneID, epoch), randomBytes(32),
            setOf(1uL), commandInspectionCapabilities(), emptySet())
        fun claim(ref: EnrollmentKeyReference) = PairingKey(ref.keyID.copyBytes(), ref.publicKey.copyBytes().takeLast(65).toByteArray())
        val proposal = PairingPhoneProposal(offer, claim(checkNotNull(transportKey)), claim(checkNotNull(decisionKey)), claim(checkNotNull(biometricKey)))
        val opened = authenticatePairingRoutes(scope,
            androidPairingRoutes(app, selected.macID.copyBytes(), selected.accountID.copyBytes()),
            arrayOf(checkNotNull(identity).identity.keyManager), selected, proposal,
            LocalNetworkSettings(app).timeoutSeconds() * 1000L)
        channel = opened; active()
        val transcript = opened.awaitTranscript()
        active(); selected.validateMacClaims(transcript); proposal.validate(transcript)
        transcript
    }

    /** Invoke only after explicit code comparison. Durable PREPARED state precedes construction of the biometric signer. */
    suspend fun confirmComparison(): AndroidPairingBiometrics = operation {
        check(!proofSubmitted)
        if (prepared) return@operation loadPreparedSigner()
        val transcript = transcript
        val selected = checkNotNull(invitation)
        val row = PhoneEnrollment(randomID(), selected.macID.copyBytes(), selected.accountID.copyBytes(), phoneID, epoch,
            selected.label, transcript.macAuthorityKey.copyBytes(), p256SPKI(transcript.macTransportKey.copyBytes()),
            checkNotNull(transportKey), checkNotNull(decisionKey), checkNotNull(biometricKey), transcript.enrollmentTag.copyBytes(), null)
        enrollment = row
        // Completion may be ambiguous on cancellation or an I/O error. From this boundary onward never delete its keys automatically.
        prepared = true
        store.prepare(row, transcript, checkNotNull(expectedRevision), selected.minimumEnvelopeVersion)
        active()
        val access = store.prepared(row.recordID, transcript); preparedAccess = access
        loadPreparedSigner()
    }

    private fun loadPreparedSigner(): AndroidPairingBiometrics {
        val access = checkNotNull(preparedAccess)
        check(access.lease.isCurrent())
        biometric?.close()
        val signing = AndroidPairingBiometrics.load(access.record, RequestElapsedClock.now(),
            System.currentTimeMillis().toULong(), RequestElapsedClock::now,
            { !closed.get() && access.lease.isCurrent() })
        biometric = signing
        return signing
    }

    /** The exact confirmed transcript and fresh hardware proof are submitted once. A lost reply retains PREPARED storage. */
    suspend fun submit(proof: ByteArray) = operation {
        check(prepared && !proofSubmitted && checkNotNull(preparedAccess).lease.isCurrent())
        val current = transcript
        require(current.verify(proof, current.biometricKey.publicKey.copyBytes(), PairingProofPurpose.PHONE_BIOMETRIC))
        proofSubmitted = true
        val receipt = checkNotNull(channel).submitProof(current.digest(), proof)
        active()
        store.activate(checkNotNull(enrollment).recordID, CborValue.Bytes(receipt))
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            preparedAccess?.lease?.close(); biometric?.close(); channel?.close(); job.cancel()
        }
    }
    /** Join from outside this owner's job. Only newly created unpublished keys may be removed. */
    suspend fun closeAndJoin() {
        close()
        withContext(NonCancellable + Dispatchers.IO) {
            channel?.closeAndJoin(); job.join()
            operations.withLock {
                biometric?.close(); identity?.close()
                preparedAccess?.let { access -> enrollment?.let { store.release(it.recordID, access.lease) } }
                if (!prepared) {
                    val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    for (ref in ownedKeys) {
                        val point = keystore.getCertificate(ref.alias)?.publicKey?.encoded?.takeLast(65)?.toByteArray()
                        if (point != null && point.contentEquals(ref.publicKey.copyBytes().takeLast(65).toByteArray())) {
                            keystore.deleteEntry(ref.alias)
                        }
                    }
                }
                ownedKeys.clear()
            }
        }
    }
    private suspend fun <T> operation(body: suspend () -> T): T = withContext(scope.coroutineContext) {
        operations.withLock { active(); body().also { active() } }
    }
    private fun active() { check(!closed.get()) }
    override fun toString() = "AndroidPairingAttempt(redacted)"
    companion object {
        private val random = SecureRandom()
        private fun randomBytes(count: Int) = ByteArray(count).also(random::nextBytes)
        private fun randomID() = randomBytes(16)
        private fun p256SPKI(point: ByteArray) = byteArrayOf(0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86.toByte(),0x48,0xce.toByte(),
            0x3d,0x02,0x01,0x06,0x08,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x03,0x01,0x07,0x03,0x42,0x00) + point
    }
}
