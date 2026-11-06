package dev.remozio.protocol

import java.security.MessageDigest

/** Session metadata, not authority to accept an operation. */
class NegotiatedChannel internal constructor(val envelopeVersion: ULong, sessionID: ByteArray, val peer: ChannelOffer) {
    val sessionID = CborValue.Bytes(sessionID)
    override fun toString() = "NegotiatedChannel(redacted)"
}

/**
 * One owner for one fresh, mutually authenticated, enrollment-bound TLS connection.
 * The host generates a fresh random nonce, enforces a deadline, and closes this owner on enrollment changes.
 * Never feed relay metadata or bytes from another connection into this owner.
 */
class ChannelNegotiation(private val local: ChannelOffer, private val trustedMinimum: ULong) : AutoCloseable {
    private var offerSent = false
    private var peer: ChannelOffer? = null
    private var result: NegotiatedChannel? = null
    private var confirmationSent = false
    private var peerConfirmed = false
    private var closed = false
    init { require(trustedMinimum > 0uL) }

    @Synchronized fun offer(): ByteArray = guarded {
        channelCheck(!offerSent)
        local.encode().also { offerSent = true }
    }

    @Synchronized fun receiveOffer(bytes: ByteArray): Unit = guarded {
        channelCheck(offerSent && peer == null)
        val remote = ChannelOffer.decode(bytes)
        channelCheck(remote.role != local.role && remote.scope == local.scope && remote.nonce != local.nonce)
        val version = CompatibilityPolicy.envelopeVersion(local.envelopeVersions, remote.envelopeVersions, trustedMinimum)
        val phone = if (local.role == ChannelRole.PHONE) local else remote
        val mac = if (local.role == ChannelRole.MAC) local else remote
        val transcript = DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.approval.channel"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Bytes(phone.encode()), 3uL to CborValue.Bytes(mac.encode()), 4uL to CborValue.Unsigned(version),
        )), CborLimits(131_200, 3, 16))
        result = NegotiatedChannel(version, MessageDigest.getInstance("SHA-256").digest(transcript), remote)
        peer = remote
    }

    /** The Mac confirms only after checking the phone's confirmation. Deliver these bytes on the owned TLS channel. */
    @Synchronized fun confirmation(): ByteArray = guarded {
        channelCheck(result != null && !confirmationSent && (local.role == ChannelRole.PHONE || peerConfirmed))
        confirmationBytes(local.role).also { confirmationSent = true }
    }

    @Synchronized fun receiveConfirmation(bytes: ByteArray): Unit = guarded {
        channelCheck(result != null && !peerConfirmed && (local.role == ChannelRole.MAC || confirmationSent))
        channelCheck(bytes.size <= 128)
        val expected = confirmationBytes(checkNotNull(peer).role)
        channelCheck(MessageDigest.isEqual(expected, bytes))
        peerConfirmed = true
    }

    @Synchronized fun confirmed(): NegotiatedChannel {
        channelCheck(!closed && confirmationSent && peerConfirmed)
        return checkNotNull(result)
    }

    @Synchronized override fun close() { closed = true; peer = null; result = null }
    private fun confirmationBytes(role: ChannelRole): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to CborValue.Unsigned(role.tag),
        2uL to checkNotNull(result).sessionID,
    )), CborLimits(128, 2, 8))
    private inline fun <T> guarded(block: () -> T): T {
        channelCheck(!closed)
        return try { block() } catch (failure: Exception) { close(); throw failure }
    }
}
