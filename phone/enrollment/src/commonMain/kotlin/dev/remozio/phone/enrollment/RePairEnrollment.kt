package dev.remozio.phone.enrollment

import dev.remozio.protocol.CborValue
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PairingPhoneProposal
import dev.remozio.protocol.PairingTranscript
import dev.remozio.protocol.RePairInvitation
import dev.remozio.protocol.validateMacClaims

/** Allocation and pre-transcript preparation live outside the enrollment rows. */
class RePairReservation(
    recordID: ByteArray,
    predecessorRecordID: ByteArray,
    epoch: ByteArray,
    val invitation: RePairInvitation,
    keyIDs: List<CborValue.Bytes>,
    val material: RePairProposalMaterial? = null,
) {
    val recordID = id(recordID)
    val predecessorRecordID = id(predecessorRecordID)
    val epoch = id(epoch)
    val keyIDs = frozenList(keyIDs)
    val macID get() = invitation.invitation.macID

    init {
        require(this.recordID != this.predecessorRecordID && this.epoch != invitation.predecessor.epoch)
        require(this.keyIDs.size == EnrollmentKeyRole.entries.size && this.keyIDs.toSet().size == this.keyIDs.size)
        require(this.keyIDs.all { it.copyBytes().size == 16 })
        material?.let {
            require(it.keys.map { key -> key.keyID } == this.keyIDs)
            require(it.keys.all { key -> key.alias == alias(key.role) })
            require(it.proposal.phone.scope == ChannelScope(
                macID.copyBytes(), invitation.invitation.accountID.copyBytes(),
                invitation.predecessor.phoneID.copyBytes(), this.epoch.copyBytes(),
            ))
            it.proposal.validateMacScope(invitation.invitation)
            require(it.proposal.replacement?.phoneID == invitation.predecessor.phoneID)
            require(it.proposal.replacement?.epoch == invitation.predecessor.epoch)
        }
    }

    fun alias(role: EnrollmentKeyRole): String =
        "remozio.${role.aliasPart}.v1." + keyIDs[role.ordinal].copyBytes().joinToString("") {
            (it.toInt() and 255).toString(16).padStart(2, '0')
        }

    internal fun withMaterial(value: RePairProposalMaterial) =
        RePairReservation(recordID.copyBytes(), predecessorRecordID.copyBytes(), epoch.copyBytes(), invitation, keyIDs, value)

    override fun toString() = "RePairReservation(redacted)"
}

class RePairProposalMaterial(val proposal: PairingPhoneProposal, keys: List<EnrollmentKeyReference>) {
    val keys = frozenList(keys)

    init {
        require(this.keys.map { it.role } == EnrollmentKeyRole.entries)
        listOf(proposal.transportKey, proposal.decisionKey, proposal.biometricKey).zip(this.keys).forEach { (claim, key) ->
            require(claim.keyID == key.keyID && claim.publicKey == CborValue.Bytes(key.pointBytes()))
        }
    }

    override fun toString() = "RePairProposalMaterial(redacted)"
}

class PreparedRePair(
    val invitation: RePairInvitation,
    val proposal: PairingPhoneProposal,
    val proofMayHaveBeenSent: Boolean,
) {
    internal fun validate(transcript: PairingTranscript) {
        proposal.validateMacScope(invitation.invitation)
        require(proposal.replacement?.phoneID == invitation.predecessor.phoneID)
        require(proposal.replacement?.epoch == invitation.predecessor.epoch)
        invitation.invitation.validateMacClaims(transcript)
        proposal.validate(transcript)
    }

    override fun toString() = "PreparedRePair(redacted)"
}

/** The envelope selects a retained predecessor. It supplies no revocation or commit evidence. */
fun rePairPredecessor(snapshot: EnrollmentSnapshot, envelope: RePairInvitation): StoredPhoneEnrollment {
    val invitation = envelope.invitation
    val previous = snapshot.entries.single {
        val row = it.enrollment
        row.macID == invitation.macID && row.accountID == invitation.accountID &&
            row.phoneID == envelope.predecessor.phoneID && row.epoch == envelope.predecessor.epoch
    }
    require(previous.phase != EnrollmentPhase.PREPARED && previous.successorRecordID == null)
    require(previous.enrollment.authorityPublicKey == invitation.authorityPublicKey)
    require(CborValue.Bytes(previous.enrollment.transportPublicKey.copyBytes().takeLast(65).toByteArray()) ==
        invitation.transportPublicKey)
    require(snapshot.entries.none {
        it !== previous && it.phase == EnrollmentPhase.ACTIVE &&
            (it.enrollment.scope == previous.enrollment.scope ||
                (it.enrollment.macID == previous.enrollment.macID && it.enrollment.phoneID == previous.enrollment.phoneID))
    })
    return previous
}
