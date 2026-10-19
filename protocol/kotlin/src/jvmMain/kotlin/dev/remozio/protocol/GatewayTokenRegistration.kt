package dev.remozio.protocol

enum class GatewayTokenFailure { INVALID_FIELDS, UNSUPPORTED_SCHEMA, INVALID_BYTES, INVALID_CONTROL }
class GatewayTokenException(val reason: GatewayTokenFailure) : IllegalArgumentException(reason.name)

/** A candidate binding, not enrollment authority. The challenge must reach the phone through the provider only. */
class GatewayTokenBinding(
    ownerID: ByteArray, macID: ByteArray, accountID: ByteArray, gatewayID: ByteArray, lifecycleEpoch: ByteArray,
    phoneID: ByteArray, enrollmentEpoch: ByteArray, candidateID: ByteArray, tokenDigest: ByteArray,
    challenge: ByteArray, enrollmentTag: ByteArray,
) {
    init {
        val sizes = listOf(ownerID.size, macID.size, accountID.size, gatewayID.size, lifecycleEpoch.size, phoneID.size,
            enrollmentEpoch.size, candidateID.size, tokenDigest.size, challenge.size, enrollmentTag.size)
        sizes.forEachIndexed { index, size -> gatewayRequire(size == if (index < 8) 16 else 32, GatewayTokenFailure.INVALID_BYTES) }
    }
    private val bytes = listOf(ownerID, macID, accountID, gatewayID, lifecycleEpoch, phoneID, enrollmentEpoch,
        candidateID, tokenDigest, challenge, enrollmentTag).map { CborValue.Bytes(it) }
    val ownerID: ByteArray get() = bytes[0].copyBytes()
    val macID: ByteArray get() = bytes[1].copyBytes()
    val accountID: ByteArray get() = bytes[2].copyBytes()
    val gatewayID: ByteArray get() = bytes[3].copyBytes()
    val lifecycleEpoch: ByteArray get() = bytes[4].copyBytes()
    val phoneID: ByteArray get() = bytes[5].copyBytes()
    val enrollmentEpoch: ByteArray get() = bytes[6].copyBytes()
    val candidateID: ByteArray get() = bytes[7].copyBytes()
    val tokenDigest: ByteArray get() = bytes[8].copyBytes()
    val challenge: ByteArray get() = bytes[9].copyBytes()
    val enrollmentTag: ByteArray get() = bytes[10].copyBytes()
    override fun equals(other: Any?): Boolean = other is GatewayTokenBinding && bytes == other.bytes
    override fun hashCode(): Int = bytes.hashCode()
    override fun toString(): String = "GatewayTokenBinding(redacted)"
    internal fun value(): CborValue = CborValue.Fields(bytes.mapIndexed { index, value -> index.toULong() to value }.toMap())
    companion object {
        internal fun decode(value: CborValue): GatewayTokenBinding {
            val fields = (value as? CborValue.Fields)?.values ?: gatewayFail(GatewayTokenFailure.INVALID_FIELDS)
            gatewayRequire(fields.keys == (0uL..10uL).toSet(), GatewayTokenFailure.INVALID_FIELDS)
            fun bytes(key: ULong): ByteArray = (fields[key] as? CborValue.Bytes)?.copyBytes() ?: gatewayFail(GatewayTokenFailure.INVALID_BYTES)
            return GatewayTokenBinding(bytes(0u), bytes(1u), bytes(2u), bytes(3u), bytes(4u), bytes(5u), bytes(6u),
                bytes(7u), bytes(8u), bytes(9u), bytes(10u))
        }
    }
}

/** A root-to-gateway claim. Signatures, freshness, replay checks and current trust remain separate. */
class GatewayTokenCandidate(
    val binding: GatewayTokenBinding, val revision: ULong, operationID: ByteArray,
    val issuedAtUnixMillis: ULong, val expiresAtUnixMillis: ULong,
) {
    init {
        gatewayRequire(revision > 0uL && operationID.size == 16 && expiresAtUnixMillis > issuedAtUnixMillis, GatewayTokenFailure.INVALID_CONTROL)
    }
    private val operation = CborValue.Bytes(operationID)
    val operationID: ByteArray get() = operation.copyBytes()
    override fun toString(): String = "GatewayTokenCandidate(redacted)"
    fun encode(limits: CborLimits): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to binding.value(), 2uL to CborValue.Unsigned(revision), 3uL to operation,
        4uL to CborValue.Unsigned(issuedAtUnixMillis), 5uL to CborValue.Unsigned(expiresAtUnixMillis),
    )), limits)
    companion object {
        fun decode(bytes: ByteArray, limits: CborLimits): GatewayTokenCandidate {
            val fields = gatewayFields(bytes, 5u, limits)
            fun uint(key: ULong): ULong = (fields[key] as? CborValue.Unsigned)?.value ?: gatewayFail(GatewayTokenFailure.INVALID_CONTROL)
            val operation = (fields[3u] as? CborValue.Bytes)?.copyBytes() ?: gatewayFail(GatewayTokenFailure.INVALID_CONTROL)
            return GatewayTokenCandidate(GatewayTokenBinding.decode(fields.getValue(1u)), uint(2u), operation, uint(4u), uint(5u))
        }
    }
}

/** Receipt of a provider challenge. Authenticate the phone channel and consume the retained candidate separately. */
class GatewayTokenProof(val binding: GatewayTokenBinding) {
    override fun toString(): String = "GatewayTokenProof(redacted)"
    fun encode(limits: CborLimits): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to binding.value(),
    )), limits)
    companion object {
        fun decode(bytes: ByteArray, limits: CborLimits): GatewayTokenProof =
            GatewayTokenProof(GatewayTokenBinding.decode(gatewayFields(bytes, 1u, limits).getValue(1u)))
    }
}

private fun gatewayFields(bytes: ByteArray, last: ULong, limits: CborLimits): Map<ULong, CborValue> {
    val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values ?: gatewayFail(GatewayTokenFailure.INVALID_FIELDS)
    gatewayRequire(fields.keys == (0uL..last).toSet(), GatewayTokenFailure.INVALID_FIELDS)
    gatewayRequire(fields[0u] == CborValue.Unsigned(1u), GatewayTokenFailure.UNSUPPORTED_SCHEMA)
    return fields
}
private fun gatewayRequire(condition: Boolean, failure: GatewayTokenFailure) { if (!condition) gatewayFail(failure) }
private fun gatewayFail(failure: GatewayTokenFailure): Nothing = throw GatewayTokenException(failure)
