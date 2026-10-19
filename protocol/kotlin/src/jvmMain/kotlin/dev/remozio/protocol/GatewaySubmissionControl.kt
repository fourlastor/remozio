package dev.remozio.protocol

enum class GatewaySubmissionKind(val wireValue: ULong) { ROTATION(4u), REVOCATION(5u) }

/** Identifies one protected registration. Incoming fields cannot establish that registration. */
class GatewaySubmissionBinding(ownerID: ByteArray, macID: ByteArray, accountID: ByteArray, gatewayID: ByteArray, lifecycleEpoch: ByteArray) {
    private val bytes = listOf(ownerID, macID, accountID, gatewayID, lifecycleEpoch).map { CborValue.Bytes(it) }
    init { submissionRequire(bytes.all { it.copyBytes().size == 16 }, GatewayTokenFailure.INVALID_BYTES) }
    val ownerID: ByteArray get() = bytes[0].copyBytes()
    val macID: ByteArray get() = bytes[1].copyBytes()
    val accountID: ByteArray get() = bytes[2].copyBytes()
    val gatewayID: ByteArray get() = bytes[3].copyBytes()
    val lifecycleEpoch: ByteArray get() = bytes[4].copyBytes()
    override fun equals(other: Any?): Boolean = other is GatewaySubmissionBinding && bytes == other.bytes
    override fun hashCode(): Int = bytes.hashCode()
    override fun toString(): String = "GatewaySubmissionBinding(redacted)"
    internal fun value(): CborValue = CborValue.Fields(bytes.mapIndexed { i, value -> i.toULong() to value }.toMap())
    companion object {
        internal fun decode(value: CborValue): GatewaySubmissionBinding {
            val fields = (value as? CborValue.Fields)?.values ?: submissionFail(GatewayTokenFailure.INVALID_FIELDS)
            submissionRequire(fields.keys == (0uL..4uL).toSet(), GatewayTokenFailure.INVALID_FIELDS)
            fun bytes(key: ULong) = (fields[key] as? CborValue.Bytes)?.copyBytes() ?: submissionFail(GatewayTokenFailure.INVALID_BYTES)
            return GatewaySubmissionBinding(bytes(0u), bytes(1u), bytes(2u), bytes(3u), bytes(4u))
        }
    }
}

/** A Root claim to replace or revoke a wake-only credential. Durable application and current trust remain separate checks. */
class GatewaySubmissionControl(
    val kind: GatewaySubmissionKind, val binding: GatewaySubmissionBinding, val revision: ULong, operationID: ByteArray,
    val issuedAtUnixMillis: ULong, val expiresAtUnixMillis: ULong, credentialID: ByteArray, publicKey: ByteArray?,
) {
    private val operation = CborValue.Bytes(operationID)
    private val credential = CborValue.Bytes(credentialID)
    private val key = publicKey?.let { CborValue.Bytes(it) }
    init {
        submissionRequire(revision > 0uL && operation.copyBytes().size == 16 && credential.copyBytes().size == 16 &&
            expiresAtUnixMillis > issuedAtUnixMillis, GatewayTokenFailure.INVALID_CONTROL)
        when (kind) {
            GatewaySubmissionKind.ROTATION -> submissionRequire(key?.copyBytes()?.let { it.size == 65 && it[0] == 4.toByte() } == true,
                GatewayTokenFailure.INVALID_BYTES)
            GatewaySubmissionKind.REVOCATION -> submissionRequire(key == null, GatewayTokenFailure.INVALID_CONTROL)
        }
    }
    val operationID: ByteArray get() = operation.copyBytes()
    val credentialID: ByteArray get() = credential.copyBytes()
    val publicKey: ByteArray? get() = key?.copyBytes()
    override fun toString(): String = "GatewaySubmissionControl(redacted)"
    fun encode(limits: CborLimits): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to binding.value(), 2uL to CborValue.Unsigned(revision), 3uL to operation,
        4uL to CborValue.Unsigned(issuedAtUnixMillis), 5uL to CborValue.Unsigned(expiresAtUnixMillis),
        6uL to CborValue.Unsigned(kind.wireValue), 7uL to credential, 8uL to (key ?: CborValue.Null))), limits)
    companion object {
        fun decode(bytes: ByteArray, limits: CborLimits): GatewaySubmissionControl {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values ?: submissionFail(GatewayTokenFailure.INVALID_FIELDS)
            submissionRequire(fields.keys == (0uL..8uL).toSet(), GatewayTokenFailure.INVALID_FIELDS)
            submissionRequire(fields[0u] == CborValue.Unsigned(1u), GatewayTokenFailure.UNSUPPORTED_SCHEMA)
            fun uint(key: ULong) = (fields[key] as? CborValue.Unsigned)?.value ?: submissionFail(GatewayTokenFailure.INVALID_CONTROL)
            fun blob(key: ULong) = (fields[key] as? CborValue.Bytes)?.copyBytes() ?: submissionFail(GatewayTokenFailure.INVALID_BYTES)
            val kind = GatewaySubmissionKind.entries.singleOrNull { it.wireValue == uint(6u) } ?: submissionFail(GatewayTokenFailure.INVALID_CONTROL)
            val key = when (val value = fields[8u]) {
                CborValue.Null -> null
                is CborValue.Bytes -> value.copyBytes()
                else -> submissionFail(GatewayTokenFailure.INVALID_BYTES)
            }
            return GatewaySubmissionControl(kind, GatewaySubmissionBinding.decode(fields.getValue(1u)), uint(2u), blob(3u),
                uint(4u), uint(5u), blob(7u), key)
        }
    }
}

private fun submissionRequire(condition: Boolean, failure: GatewayTokenFailure) { if (!condition) submissionFail(failure) }
private fun submissionFail(failure: GatewayTokenFailure): Nothing = throw GatewayTokenException(failure)
