package dev.remozio.protocol

enum class RoutingControlFailure { INVALID_FIELDS, UNSUPPORTED_SCHEMA, INVALID_BYTES, INVALID_CONTROL, UNSUPPORTED_MODE }
class RoutingControlException(val reason: RoutingControlFailure) : IllegalArgumentException(reason.name)

/** A phone claim to route requests Away. Current enrollment, challenge, expiry and revision need authority checks. */
class RoutingAwayControl(
    macID: ByteArray, accountID: ByteArray, phoneID: ByteArray, enrollmentEpoch: ByteArray, operationID: ByteArray,
    challenge: ByteArray, keyID: ByteArray, val expectedRevision: ULong,
    val issuedAtUnixMillis: ULong, val expiresAtUnixMillis: ULong,
) {
    init {
        routingRequire(listOf(macID, accountID, phoneID, enrollmentEpoch, operationID, keyID).all { it.size == 16 } &&
            challenge.size == 32, RoutingControlFailure.INVALID_BYTES)
        routingRequire(expiresAtUnixMillis > issuedAtUnixMillis, RoutingControlFailure.INVALID_CONTROL)
    }
    private val bytes = listOf(macID, accountID, phoneID, enrollmentEpoch, operationID, challenge, keyID).map { CborValue.Bytes(it) }
    val macID: ByteArray get() = bytes[0].copyBytes()
    val accountID: ByteArray get() = bytes[1].copyBytes()
    val phoneID: ByteArray get() = bytes[2].copyBytes()
    val enrollmentEpoch: ByteArray get() = bytes[3].copyBytes()
    val operationID: ByteArray get() = bytes[4].copyBytes()
    val challenge: ByteArray get() = bytes[5].copyBytes()
    val keyID: ByteArray get() = bytes[6].copyBytes()
    override fun toString(): String = "RoutingAwayControl(redacted)"
    fun encode(limits: CborLimits): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to bytes[0], 2uL to bytes[1], 3uL to bytes[2], 4uL to bytes[3],
        5uL to bytes[4], 6uL to bytes[5], 7uL to bytes[6], 8uL to CborValue.Unsigned(expectedRevision),
        9uL to CborValue.Unsigned(issuedAtUnixMillis), 10uL to CborValue.Unsigned(expiresAtUnixMillis), 11uL to CborValue.Unsigned(2u),
    )), limits)
    companion object {
        fun decode(payload: ByteArray, limits: CborLimits): RoutingAwayControl {
            val fields = (DeterministicCbor.decode(payload, limits) as? CborValue.Fields)?.values ?: routingFail(RoutingControlFailure.INVALID_FIELDS)
            routingRequire(fields.keys == (0uL..11uL).toSet(), RoutingControlFailure.INVALID_FIELDS)
            routingRequire(fields[0u] == CborValue.Unsigned(1u), RoutingControlFailure.UNSUPPORTED_SCHEMA)
            routingRequire(fields[11u] == CborValue.Unsigned(2u), RoutingControlFailure.UNSUPPORTED_MODE)
            fun bytes(key: ULong): ByteArray = (fields[key] as? CborValue.Bytes)?.copyBytes() ?: routingFail(RoutingControlFailure.INVALID_BYTES)
            fun uint(key: ULong): ULong = (fields[key] as? CborValue.Unsigned)?.value ?: routingFail(RoutingControlFailure.INVALID_CONTROL)
            return RoutingAwayControl(bytes(1u), bytes(2u), bytes(3u), bytes(4u), bytes(5u), bytes(6u), bytes(7u), uint(8u), uint(9u), uint(10u))
        }
    }
}

object RoutingAwaySigningInput {
    fun make(wireVersion: ULong, canonicalPayload: ByteArray, payloadLimits: CborLimits, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        if (canonicalPayload.size > payloadLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        val payload = canonicalPayload.copyOf()
        RoutingAwayControl.decode(payload, payloadLimits)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.routing"), 1uL to CborValue.Unsigned(wireVersion),
            2uL to CborValue.Unsigned(1u), 3uL to CborValue.Unsigned(1u), 4uL to CborValue.Bytes(payload),
        )), inputLimits)
    }
}

/** Select only the current enrolled decision key. A valid signature alone cannot change routing or grant approval. */
object RoutingAwaySignature {
    fun verify(signature: ByteArray, publicKey: ByteArray, wireVersion: ULong, canonicalPayload: ByteArray,
               payloadLimits: CborLimits, inputLimits: CborLimits): Boolean = P256Verification.verify(
        signature, publicKey, RoutingAwaySigningInput.make(wireVersion, canonicalPayload, payloadLimits, inputLimits))
}

private fun routingRequire(condition: Boolean, failure: RoutingControlFailure) { if (!condition) routingFail(failure) }
private fun routingFail(failure: RoutingControlFailure): Nothing = throw RoutingControlException(failure)
