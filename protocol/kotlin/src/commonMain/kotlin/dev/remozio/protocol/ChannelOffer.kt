package dev.remozio.protocol

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
    val features: Set<ULong> = readOnlySnapshot(features)
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
    val envelopeVersions: Set<ULong> = readOnlySnapshot(envelopeVersions)
    val requests: List<ChannelRequestCapability> = readOnlySnapshot(requests.sortedWith(
        compareBy({ it.kind }, { it.wireVersion }, { it.schemaVersion })))
    val auditVersions: Set<ULong> = readOnlySnapshot(auditVersions)
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

internal val OFFER_LIMITS = CborLimits(65_536, 5, 5000)
internal fun numbers(values: Set<ULong>) = CborValue.ArrayValue(values.sorted().map { CborValue.Unsigned(it) })
internal fun numberSet(value: CborValue?, maximum: Int): Set<ULong> {
    val values = (value as? CborValue.ArrayValue)?.values ?: rejectChannel()
    channelCheck(values.size <= maximum)
    val numbers = values.map { (it as? CborValue.Unsigned)?.value ?: rejectChannel() }
    channelCheck(numbers.zipWithNext().all { (a, b) -> a < b })
    return numbers.toSet()
}
internal fun channelCheck(condition: Boolean) { if (!condition) rejectChannel() }
internal fun rejectChannel(): Nothing = throw ChannelNegotiationException()
