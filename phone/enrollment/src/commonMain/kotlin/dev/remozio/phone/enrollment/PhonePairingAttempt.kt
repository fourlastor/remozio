package dev.remozio.phone.enrollment

import dev.remozio.protocol.CborValue
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PairingProofPurpose
import dev.remozio.protocol.PairingTranscript

/** Local setup owner. Construct only after independent Mac authentication and human transcript verification. */
class PhonePairingAttempt(
    val transcript: PairingTranscript,
    prepared: StoredPhoneEnrollment,
    authorizedReplacement: StoredPhoneEnrollment?,
    minimumEnvelopeVersion: ULong,
) {
    private val expected = EnrollmentEncoding.encode(prepared)
    private val enrollment = prepared.enrollment
    private val replacement = authorizedReplacement?.let(EnrollmentEncoding::encode)
    private val replacementID = authorizedReplacement?.enrollment?.recordID

    init {
        require(prepared.phase == EnrollmentPhase.PREPARED)
        val retained = requireNotNull(prepared.pairing)
        require(retained.transcript.encode().contentEquals(transcript.encode()))
        require(retained.minimumEnvelopeVersion == minimumEnvelopeVersion)
        require(retained.replacingRecordID == replacementID)
        require(transcript.minimumEnvelopeVersion == minimumEnvelopeVersion)
        require(transcript.phone.scope == ChannelScope(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(),
            enrollment.phoneID.copyBytes(), enrollment.epoch.copyBytes()))
        require(transcript.macAuthorityKey == enrollment.authorityPublicKey)
        require(transcript.macTransportKey == CborValue.Bytes(enrollment.transportPublicKey.copyBytes().takeLast(65).toByteArray()))
        require(transcript.enrollmentTag == enrollment.enrollmentTag)
        listOf(transcript.transportKey, transcript.decisionKey, transcript.biometricKey).zip(enrollment.keys).forEach { (claim, local) ->
            require(claim.keyID == local.keyID && claim.publicKey == CborValue.Bytes(local.pointBytes()))
        }
        require(transcript.replacement?.phoneID == authorizedReplacement?.enrollment?.phoneID)
        require(transcript.replacement?.epoch == authorizedReplacement?.enrollment?.epoch)
        authorizedReplacement?.let {
            require(it.phase == EnrollmentPhase.ACTIVE && it.enrollment.scope == enrollment.scope)
            require(it.enrollment.recordID != enrollment.recordID)
        }
    }

    /** A late receipt can reconcile a completed setup. It cannot revive a removed local record. */
    fun activate(store: EncryptedEnrollmentStore, signature: ByteArray): EnrollmentSnapshot {
        require(transcript.verify(signature, enrollment.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
        val snapshot = store.snapshot()
        val current = snapshot.entries.single { it.enrollment.recordID == enrollment.recordID }
        require(EnrollmentEncoding.encode(current) == expected)
        val active = snapshot.entries.singleOrNull { it.enrollment.scope == enrollment.scope && it.phase == EnrollmentPhase.ACTIVE }
        require(active?.let(EnrollmentEncoding::encode) == replacement)
        return store.activate(enrollment.recordID.copyBytes(), snapshot.revision, replacementID?.copyBytes())
    }

    override fun toString() = "PhonePairingAttempt(redacted)"
}
