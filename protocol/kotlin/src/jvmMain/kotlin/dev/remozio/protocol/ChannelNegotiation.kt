package dev.remozio.protocol

import java.security.MessageDigest
import java.util.Collections

/** Roles have fixed wire tags; enum ordering is not the wire contract. */
enum class ChannelRole(val tag: ULong) { PHONE(0u), MAC(1u) }
class ChannelNegotiationException : IllegalArgumentException("Channel negotiation rejected")

class ChannelScope(macID: ByteArray, accountID: ByteArray, phoneID: ByteArray, enrollmentEpoch: ByteArray) {
    internal val value = CborValue.ArrayValue(listOf(macID, accountID, phoneID, enrollmentEpoch).map {
        require(it.size == 16); CborValue.Bytes(it)
    })
    override fun equals(other: Any?) = other is ChannelScope && value == other.value
    override fun hashCode() = value.hashCode()
    override fun toString() = "ChannelScope(redacted)"
}

/** Unknown kinds remain opaque; their presence never enables a renderer or action verifier. */
class ChannelRequestCapability(val kind: ULong, val wireVersion: ULong, val schemaVersion: ULong, features: Set<ULong>) {
    val features: Set<ULong> = Collections.unmodifiableSet(HashSet(features))
    init { require(wireVersion > 0uL && schemaVersion > 0uL && features.size <= 64) }
    internal val identity get() = Triple(kind, wireVersion, schemaVersion)
    internal fun value() = CborValue.ArrayValue(listOf(CborValue.Unsigned(kind), CborValue.Unsigned(wireVersion),
        CborValue.Unsigned(schemaVersion), numbers(features)))
}

/** Parsed offers are untrusted until the host confirms them over the same enrolled TLS connection. */
class ChannelOffer(
    val role: ChannelRole, val scope: ChannelScope, nonce: ByteArray, envelopeVersions: Set<ULong>,
    requests: List<ChannelRequestCapability>, auditVersions: Set<ULong>,
) {
    val nonce = CborValue.Bytes(nonce)
    val envelopeVersions: Set<ULong> = Collections.unmodifiableSet(HashSet(envelopeVersions))
    val requests: List<ChannelRequestCapability> = Collections.unmodifiableList(ArrayList(requests.sortedWith(
        compareBy({ it.kind }, { it.wireVersion }, { it.schemaVersion }))))
    val auditVersions: Set<ULong> = Collections.unmodifiableSet(HashSet(auditVersions))
    init {
        require(nonce.size == 32 && envelopeVersions.size in 1..16 && envelopeVersions.all { it > 0uL })
        require(auditVersions.size <= 16 && auditVersions.all { it > 0uL })
        require(requests.size <= 64 && requests.map { it.identity }.toSet().size == requests.size)
    }
    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to CborValue.Unsigned(role.tag), 2uL to scope.value,
        3uL to nonce, 4uL to numbers(envelopeVersions),
        5uL to CborValue.ArrayValue(requests.map { it.value() }), 6uL to numbers(auditVersions),
    )), OFFER_LIMITS)
    override fun toString() = "ChannelOffer(redacted)"

    companion object {
        fun decode(bytes: ByteArray): ChannelOffer {
            val fields = (DeterministicCbor.decode(bytes, OFFER_LIMITS) as? CborValue.Fields)?.values ?: rejectChannel()
            channelCheck(fields.keys == (0uL..6uL).toSet() && fields[0u] == CborValue.Unsigned(1u))
            val role = ChannelRole.entries.singleOrNull { fields[1u] == CborValue.Unsigned(it.tag) } ?: rejectChannel()
            val scope = (fields[2u] as? CborValue.ArrayValue)?.values ?: rejectChannel()
            channelCheck(scope.size == 4)
            fun scopeBytes(i: Int) = (scope[i] as? CborValue.Bytes)?.copyBytes() ?: rejectChannel()
            val nonce = (fields[3u] as? CborValue.Bytes)?.copyBytes() ?: rejectChannel()
            val rows = (fields[5u] as? CborValue.ArrayValue)?.values ?: rejectChannel()
            channelCheck(rows.size <= 64)
            val requests = rows.map { row ->
                val values = (row as? CborValue.ArrayValue)?.values ?: rejectChannel()
                channelCheck(values.size == 4)
                fun uint(i: Int) = (values[i] as? CborValue.Unsigned)?.value ?: rejectChannel()
                ChannelRequestCapability(uint(0), uint(1), uint(2), numberSet(values[3], 64))
            }
            val result = ChannelOffer(role, ChannelScope(scopeBytes(0), scopeBytes(1), scopeBytes(2), scopeBytes(3)),
                nonce, numberSet(fields[4u], 16), requests, numberSet(fields[6u], 16))
            channelCheck(result.encode().contentEquals(bytes))
            return result
        }
    }
}

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

private val OFFER_LIMITS = CborLimits(65_536, 5, 5000)
private fun numbers(values: Set<ULong>) = CborValue.ArrayValue(values.sorted().map { CborValue.Unsigned(it) })
private fun numberSet(value: CborValue?, maximum: Int): Set<ULong> {
    val values = (value as? CborValue.ArrayValue)?.values ?: rejectChannel()
    channelCheck(values.size <= maximum)
    val numbers = values.map { (it as? CborValue.Unsigned)?.value ?: rejectChannel() }
    channelCheck(numbers.zipWithNext().all { (a, b) -> a < b })
    return numbers.toSet()
}
private fun channelCheck(condition: Boolean) { if (!condition) rejectChannel() }
private fun rejectChannel(): Nothing = throw ChannelNegotiationException()
