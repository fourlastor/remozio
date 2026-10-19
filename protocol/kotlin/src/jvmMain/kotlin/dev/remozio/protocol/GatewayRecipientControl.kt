package dev.remozio.protocol

enum class GatewayRecipientKind(val wireValue: ULong) { ACTIVATION(2u), PHONE_REVOCATION(3u) }

/** Identifies one enrolled phone epoch within one registered gateway lifecycle. */
class GatewayPhoneEpochBinding(
    ownerID: ByteArray, macID: ByteArray, accountID: ByteArray, gatewayID: ByteArray, lifecycleEpoch: ByteArray,
    phoneID: ByteArray, enrollmentEpoch: ByteArray,
) {
    init {
        recipientRequire(listOf(ownerID.size, macID.size, accountID.size, gatewayID.size, lifecycleEpoch.size, phoneID.size,
            enrollmentEpoch.size).all { it == 16 }, GatewayTokenFailure.INVALID_BYTES)
    }
    private val bytes = listOf(ownerID, macID, accountID, gatewayID, lifecycleEpoch, phoneID, enrollmentEpoch).map { CborValue.Bytes(it) }
    val ownerID: ByteArray get() = bytes[0].copyBytes()
    val macID: ByteArray get() = bytes[1].copyBytes()
    val accountID: ByteArray get() = bytes[2].copyBytes()
    val gatewayID: ByteArray get() = bytes[3].copyBytes()
    val lifecycleEpoch: ByteArray get() = bytes[4].copyBytes()
    val phoneID: ByteArray get() = bytes[5].copyBytes()
    val enrollmentEpoch: ByteArray get() = bytes[6].copyBytes()
    override fun equals(other: Any?): Boolean = other is GatewayPhoneEpochBinding && bytes == other.bytes
    override fun hashCode(): Int = bytes.hashCode()
    override fun toString(): String = "GatewayPhoneEpochBinding(redacted)"
    internal fun value(): CborValue = CborValue.Fields(bytes.mapIndexed { index, value -> index.toULong() to value }.toMap())
    companion object {
        internal fun decode(value: CborValue): GatewayPhoneEpochBinding {
            val fields = (value as? CborValue.Fields)?.values ?: recipientFail(GatewayTokenFailure.INVALID_FIELDS)
            recipientRequire(fields.keys == (0uL..6uL).toSet(), GatewayTokenFailure.INVALID_FIELDS)
            fun bytes(key: ULong) = (fields[key] as? CborValue.Bytes)?.copyBytes() ?: recipientFail(GatewayTokenFailure.INVALID_BYTES)
            return GatewayPhoneEpochBinding(bytes(0u), bytes(1u), bytes(2u), bytes(3u), bytes(4u), bytes(5u), bytes(6u))
        }
    }
}

/** A root claim for a verified candidate. Current trust, candidate expiry and one-time consumption remain separate. */
class GatewayMappingActivation(
    val binding: GatewayTokenBinding, val revision: ULong, operationID: ByteArray,
    val issuedAtUnixMillis: ULong, val expiresAtUnixMillis: ULong,
) {
    init { validateRecipientMetadata(revision, operationID, issuedAtUnixMillis, expiresAtUnixMillis) }
    private val operation = CborValue.Bytes(operationID)
    val operationID: ByteArray get() = operation.copyBytes()
    override fun toString(): String = "GatewayMappingActivation(redacted)"
    fun encode(limits: CborLimits): ByteArray = encodeRecipient(binding.value(), revision, operation,
        issuedAtUnixMillis, expiresAtUnixMillis, GatewayRecipientKind.ACTIVATION, limits)
    companion object {
        fun decode(bytes: ByteArray, limits: CborLimits): GatewayMappingActivation {
            val fields = recipientFields(bytes, GatewayRecipientKind.ACTIVATION, limits)
            val metadata = recipientMetadata(fields)
            return GatewayMappingActivation(GatewayTokenBinding.decode(fields.getValue(1u)), metadata.revision, metadata.operation,
                metadata.issued, metadata.expires)
        }
    }
}

/** A root revocation claim. Application requires durable tombstones and current registration verification. */
class GatewayPhoneRevocation(
    val binding: GatewayPhoneEpochBinding, val revision: ULong, operationID: ByteArray,
    val issuedAtUnixMillis: ULong, val expiresAtUnixMillis: ULong,
) {
    init { validateRecipientMetadata(revision, operationID, issuedAtUnixMillis, expiresAtUnixMillis) }
    private val operation = CborValue.Bytes(operationID)
    val operationID: ByteArray get() = operation.copyBytes()
    override fun toString(): String = "GatewayPhoneRevocation(redacted)"
    fun encode(limits: CborLimits): ByteArray = encodeRecipient(binding.value(), revision, operation,
        issuedAtUnixMillis, expiresAtUnixMillis, GatewayRecipientKind.PHONE_REVOCATION, limits)
    companion object {
        fun decode(bytes: ByteArray, limits: CborLimits): GatewayPhoneRevocation {
            val fields = recipientFields(bytes, GatewayRecipientKind.PHONE_REVOCATION, limits)
            val metadata = recipientMetadata(fields)
            return GatewayPhoneRevocation(GatewayPhoneEpochBinding.decode(fields.getValue(1u)), metadata.revision, metadata.operation,
                metadata.issued, metadata.expires)
        }
    }
}

private data class RecipientMetadata(val revision: ULong, val operation: ByteArray, val issued: ULong, val expires: ULong)
private fun validateRecipientMetadata(revision: ULong, operation: ByteArray, issued: ULong, expires: ULong) {
    recipientRequire(revision > 0uL && operation.size == 16 && expires > issued, GatewayTokenFailure.INVALID_CONTROL)
}
private fun encodeRecipient(binding: CborValue, revision: ULong, operation: CborValue.Bytes, issued: ULong,
                            expires: ULong, kind: GatewayRecipientKind, limits: CborLimits): ByteArray =
    DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Unsigned(1u), 1uL to binding,
        2uL to CborValue.Unsigned(revision), 3uL to operation, 4uL to CborValue.Unsigned(issued), 5uL to CborValue.Unsigned(expires),
        6uL to CborValue.Unsigned(kind.wireValue))), limits)
private fun recipientFields(bytes: ByteArray, kind: GatewayRecipientKind, limits: CborLimits): Map<ULong, CborValue> {
    val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values ?: recipientFail(GatewayTokenFailure.INVALID_FIELDS)
    recipientRequire(fields.keys == (0uL..6uL).toSet(), GatewayTokenFailure.INVALID_FIELDS)
    recipientRequire(fields[0u] == CborValue.Unsigned(1u), GatewayTokenFailure.UNSUPPORTED_SCHEMA)
    recipientRequire(fields[6u] == CborValue.Unsigned(kind.wireValue), GatewayTokenFailure.INVALID_CONTROL)
    return fields
}
private fun recipientMetadata(fields: Map<ULong, CborValue>): RecipientMetadata {
    fun uint(key: ULong) = (fields[key] as? CborValue.Unsigned)?.value ?: recipientFail(GatewayTokenFailure.INVALID_CONTROL)
    val operation = (fields[3u] as? CborValue.Bytes)?.copyBytes() ?: recipientFail(GatewayTokenFailure.INVALID_CONTROL)
    return RecipientMetadata(uint(2u), operation, uint(4u), uint(5u))
}
private fun recipientRequire(condition: Boolean, failure: GatewayTokenFailure) { if (!condition) recipientFail(failure) }
private fun recipientFail(failure: GatewayTokenFailure): Nothing = throw GatewayTokenException(failure)
