package dev.sebastiano.remozio.android.enrollment

import android.content.Context
import dev.sebastiano.remozio.android.biometrics.AndroidBiometricKeyCreation
import dev.sebastiano.remozio.android.biometrics.AndroidPairingBiometrics
import dev.sebastiano.remozio.android.decisions.AndroidDecisionKeyCreation
import dev.sebastiano.remozio.android.requests.RequestElapsedClock
import dev.sebastiano.remozio.android.requests.commandInspectionCapabilities
import dev.sebastiano.remozio.android.transport.AndroidTransportKeyCreation
import dev.sebastiano.remozio.android.transport.CreatedTransportIdentity
import dev.sebastiano.remozio.android.transport.LocalNetworkSettings
import dev.sebastiano.remozio.android.transport.androidPairingRoutes
import dev.remozio.phone.enrollment.*
import dev.remozio.pairing.PairingSetupChannel
import dev.remozio.protocol.*
import java.security.KeyStore
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.*
import dev.remozio.phone.transport.authenticatePairingRoutes
import dev.remozio.phone.transport.authenticatePairingV2Routes
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** One explicit setup owner. No network input can select a retained record or activate it without its Root receipt. */
internal class AndroidPairingAttempt(
    parent: CoroutineScope,
    private val store: StoredPairingHost,
    private val application: () -> Context,
    private val createTransportKey: (Instant, ByteArray) -> CreatedTransportIdentity,
) : AutoCloseable {
    constructor(context: Context, parent: CoroutineScope, store: StoredPairingHost) : this(
        parent, store, { context.applicationContext }, { now, keyID ->
            AndroidTransportKeyCreation.createForEnrollment(context.applicationContext,
                now.minusSeconds(300), now.plusSeconds(31_536_000), keyID)
        },
    )
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
    private var preparedRecord: StoredPhoneEnrollment? = null
    private var prepared = false
    private var preparedAccess: PreparedPairingAccess? = null
    private var biometric: AndroidPairingBiometrics? = null
    private var proofSubmitted = false
    private var rePairRecordID: CborValue.Bytes? = null
    private var phoneID = randomID()
    private val epoch = randomID()
    val phoneSuffix: String get() = phoneID.takeLast(4).joinToString("") { "%02X".format(it.toInt() and 255) }
    val transcript: PairingTranscript get() = checkNotNull(channel).transcript

    suspend fun connect(text: String): PairingTranscript {
        val imported = text.trim()
        val rePair = if (imported.startsWith("remozio-repair:")) RePairInvitation.importText(imported) else null
        return connect(rePair?.invitation ?: PairingInvitation.importText(imported), rePair, null)
    }

    suspend fun connectV2(invitation: PairingInvitationV2): PairingTranscript = connect(
        invitation.invitation, invitation.replacement?.let { RePairInvitation(invitation.invitation, it) }, invitation,
    )

    private suspend fun connect(selected: PairingInvitation, rePair: RePairInvitation?,
        v2: PairingInvitationV2?,
    ): PairingTranscript = operation {
        check(invitation == null)
        val keyIDs = EnrollmentKeyRole.entries.map { CborValue.Bytes(randomID()) }
        if (rePair == null) {
            val snapshot = store.setupSnapshot()
            require(snapshot.entries.size + snapshot.rePairReservations.size < 1024)
            require(snapshot.rePairReservations.none { it.macID == selected.macID })
            require(snapshot.entries.none {
                it.phase != EnrollmentPhase.REMOVED && it.enrollment.macID == selected.macID &&
                    it.enrollment.accountID == selected.accountID &&
                    (it.phase == EnrollmentPhase.ACTIVE || it.rePair?.proofMayHaveBeenSent != true)
            })
            expectedRevision = snapshot.revision
        } else {
            phoneID = rePair.predecessor.phoneID.copyBytes()
            val recordID = randomID()
            withContext(NonCancellable) {
                val reserved = store.reserveRePair(rePair, recordID, epoch, keyIDs)
                rePairRecordID = reserved.recordID
            }
        }
        invitation = selected
        // Provider calls cannot be interrupted safely. Each returned key belongs to the chosen attempt.
        withContext(NonCancellable + Dispatchers.IO) {
            active()
            val now = Instant.now()
            val transportID = keyIDs[EnrollmentKeyRole.TRANSPORT.ordinal].copyBytes()
            val made = createTransportKey(now, transportID)
            identity = made
            val transport = EnrollmentKeyReference(EnrollmentKeyRole.TRANSPORT, transportID, made.alias, made.publicKey())
            transportKey = transport
            ownedKeys.add(transport)
            active()
            val decision = AndroidDecisionKeyCreation.createForEnrollment(application(), keyIDs[EnrollmentKeyRole.DECISION.ordinal].copyBytes())
            decisionKey = decision
            ownedKeys.add(decision)
            active()
            val bio = AndroidBiometricKeyCreation.createForEnrollment(application(), keyIDs[EnrollmentKeyRole.BIOMETRIC.ordinal].copyBytes())
            biometricKey = bio
            ownedKeys.add(bio)
        }
        active()
        val offer = ChannelOffer(ChannelRole.PHONE,
            ChannelScope(selected.macID.copyBytes(), selected.accountID.copyBytes(), phoneID, epoch), randomBytes(32),
            setOf(1uL), commandInspectionCapabilities(), emptySet())
        fun claim(ref: EnrollmentKeyReference) = PairingKey(ref.keyID.copyBytes(), ref.publicKey.copyBytes().takeLast(65).toByteArray())
        val proposal = PairingPhoneProposal(offer, claim(checkNotNull(transportKey)), claim(checkNotNull(decisionKey)),
            claim(checkNotNull(biometricKey)), rePair?.predecessor)
        active()
        val routes = androidPairingRoutes(application(), selected, v2)
        val keys = arrayOf<javax.net.ssl.KeyManager>(checkNotNull(identity).identity.keyManager)
        val timeout = LocalNetworkSettings(application()).timeoutSeconds() * 1000L
        val opened = if (v2 == null) authenticatePairingRoutes(scope, routes, keys, selected, proposal, timeout)
            else authenticatePairingV2Routes(scope, routes, keys, v2, proposal, timeout, AndroidInvitationExporter)
        channel = opened; active()
        val prepareProposal: suspend () -> Unit = {
            rePairRecordID?.let { store.prepareRePairProposal(it, RePairProposalMaterial(proposal, ownedKeys)) }
        }
        val transcript = if (v2 == null) opened.awaitTranscript(prepareProposal)
            else opened.awaitTranscriptV2(v2, prepareProposal)
        active()
        selected.validateMacClaims(transcript)
        proposal.validate(transcript)
        rePairRecordID?.let {
            val checkpoint = store.checkpointRePair(it, transcript)
            preparedRecord = checkpoint
            enrollment = checkpoint.enrollment
        }
        transcript
    }

    /** Invoke only after explicit code comparison. Durable PREPARED state precedes construction of the biometric signer. */
    suspend fun confirmComparison(): AndroidPairingBiometrics = operation {
        check(!proofSubmitted)
        if (prepared) return@operation loadPreparedSigner()
        val transcript = transcript
        rePairRecordID?.let {
            preparedAccess = store.prepared(it, transcript)
            prepared = true
            return@operation loadPreparedSigner()
        }
        val selected = checkNotNull(invitation)
        val row = PhoneEnrollment(randomID(), selected.macID.copyBytes(), selected.accountID.copyBytes(), phoneID, epoch,
            selected.label, transcript.macAuthorityKey.copyBytes(), p256SPKI(transcript.macTransportKey.copyBytes()),
            checkNotNull(transportKey), checkNotNull(decisionKey), checkNotNull(biometricKey), transcript.enrollmentTag.copyBytes(), null)
        enrollment = row
        preparedRecord = StoredPhoneEnrollment(row, EnrollmentPhase.PREPARED,
            PreparedPairing(transcript, null, selected.minimumEnvelopeVersion))
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
        val receipt = checkNotNull(channel).submitProof(current.digest(), proof) {
            if (rePairRecordID != null) preparedAccess = store.markRePairProof(checkNotNull(preparedAccess))
            active()
            proofSubmitted = true
        }
        active()
        store.activate(checkNotNull(enrollment).recordID, CborValue.Bytes(receipt),
            expected = if (rePairRecordID != null) preparedAccess else null)
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            preparedAccess?.lease?.close(); biometric?.close(); channel?.close(); job.cancel()
        }
    }
    /** Join before cleanup. A proof submission keeps its record and keys even when delivery failed. */
    suspend fun closeAndJoin() {
        close()
        withContext(NonCancellable + Dispatchers.IO) {
            channel?.closeAndJoin(); job.join()
            operations.withLock {
                val rePairID = rePairRecordID
                try {
                    biometric?.close()
                    identity?.close()
                    preparedAccess?.let { access -> enrollment?.let { store.release(it.recordID, access.lease) } }
                    if (rePairID == null) {
                        if (!prepared) retireOwnedKeys()
                        else if (!proofSubmitted) store.abandonUnsubmitted(checkNotNull(preparedRecord), ::retireOwnedKeys)
                    }
                } finally {
                    if (rePairID != null) store.finishRePair(rePairID)
                    ownedKeys.clear()
                }
            }
        }
    }
    private fun retireOwnedKeys() {
        if (ownedKeys.isEmpty()) return
        val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (ref in ownedKeys) {
            val point = keystore.getCertificate(ref.alias)?.publicKey?.encoded?.takeLast(65)?.toByteArray()
            if (point != null && point.contentEquals(ref.publicKey.copyBytes().takeLast(65).toByteArray())) {
                keystore.deleteEntry(ref.alias)
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
