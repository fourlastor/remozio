package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException

/** One read-only query. A missing receipt gives no evidence that the Mac did not commit enrollment. */
class PairingReceiptChannel private constructor(
    private val channel: NegotiatedTLSChannel,
    private val record: StoredPhoneEnrollment,
) : AutoCloseable {
    private val used = AtomicBoolean(false)
    suspend fun recover(): ByteArray? {
        try {
            check(used.compareAndSet(false, true))
            val transcript = checkNotNull(record.pairing).transcript
            channel.send(PairingReceiptFrame.Query(transcript.setupID.copyBytes()).encode())
            val bytes = channel.receive() ?: throw IOException("Missing pairing receipt")
            val reply = PairingReceiptFrame.decode(bytes) as? PairingReceiptFrame.Response
                ?: throw IOException("Invalid pairing receipt")
            require(reply.setupID == transcript.setupID)
            val proof = reply.signature?.copyBytes() ?: return null
            require(transcript.verify(proof, record.enrollment.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
            return proof
        } catch (cancelled: CancellationException) { close(); throw cancelled }
        catch (_: Exception) { close(); throw IOException("Pairing receipt unavailable") }
    }
    override fun close() = channel.close()
    suspend fun closeAndJoin() = channel.closeAndJoin()
    override fun toString() = "PairingReceiptChannel(redacted)"

    companion object {
        /** The connector has authenticated the retained transport pin and the receipt ALPN. No fresh authority is created here. */
        fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel): PairingReceiptChannel {
            try {
                require(record.phase == EnrollmentPhase.PREPARED)
                val enrollment = record.enrollment
                val pairing = requireNotNull(record.pairing)
                val scope = ChannelScope(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(),
                    enrollment.phoneID.copyBytes(), enrollment.epoch.copyBytes())
                val peer = channel.negotiated
                require(channel.purpose == EnrolledChannelPurpose.PAIRING_RECEIPT &&
                    channel.localRequests.isEmpty() && channel.localAuditVersions.isEmpty())
                require(peer.peer.role == ChannelRole.MAC && peer.peer.scope == scope && peer.envelopeVersion == 1uL &&
                    peer.envelopeVersion >= pairing.minimumEnvelopeVersion)
                require(pairing.transcript.phone.scope == scope && pairing.transcript.macAuthorityKey == enrollment.authorityPublicKey)
                return PairingReceiptChannel(channel, record)
            } catch (failure: Exception) { channel.close(); throw failure }
        }
    }
}
