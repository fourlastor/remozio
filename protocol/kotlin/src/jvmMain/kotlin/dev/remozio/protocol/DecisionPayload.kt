package dev.remozio.protocol

enum class DecisionPayloadFailure { INVALID_FIELDS, UNSUPPORTED_SCHEMA, INVALID_BYTES, INVALID_ACTION }
class DecisionPayloadException(val reason: DecisionPayloadFailure) : IllegalArgumentException(reason.name)

/** A parsed claim. Enrollment, signatures, retained bindings, and consumption still require validation. */
class DecisionPayload(
    macID: ByteArray,
    accountID: ByteArray,
    requestID: ByteArray,
    requestDigest: ByteArray,
    challenge: ByteArray,
    phoneID: ByteArray,
    keyID: ByteArray,
    val action: CapturedAction,
) {
    init {
        ensure(listOf(macID.size, accountID.size, requestID.size, requestDigest.size, challenge.size, phoneID.size, keyID.size) == listOf(16, 16, 16, 32, 32, 16, 16), DecisionPayloadFailure.INVALID_BYTES)
        ensure(action.scope !is ActionScope.Timed || action.scope.seconds > 0uL, DecisionPayloadFailure.INVALID_ACTION)
    }

    private val bytes = listOf(macID, accountID, requestID, requestDigest, challenge, phoneID, keyID).map { CborValue.Bytes(it) }
    val macID: ByteArray get() = bytes[0].copyBytes()
    val accountID: ByteArray get() = bytes[1].copyBytes()
    val requestID: ByteArray get() = bytes[2].copyBytes()
    val requestDigest: ByteArray get() = bytes[3].copyBytes()
    val challenge: ByteArray get() = bytes[4].copyBytes()
    val phoneID: ByteArray get() = bytes[5].copyBytes()
    val keyID: ByteArray get() = bytes[6].copyBytes()

    fun encode(limits: CborLimits): ByteArray {
        val fields = mutableMapOf<ULong, CborValue>(0uL to CborValue.Unsigned(1u))
        bytes.forEachIndexed { index, value -> fields[(index + 1).toULong()] = value }
        fields[8u] = ActionWire.encode(action)
        return DeterministicCbor.encode(CborValue.Fields(fields), limits)
    }

    companion object {
        fun decode(bytes: ByteArray, limits: CborLimits): DecisionPayload {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values
                ?: fail(DecisionPayloadFailure.INVALID_FIELDS)
            ensure(fields.keys == (0uL..8uL).toSet(), DecisionPayloadFailure.INVALID_FIELDS)
            ensure(fields[0u] == CborValue.Unsigned(1u), DecisionPayloadFailure.UNSUPPORTED_SCHEMA)
            fun data(key: ULong): ByteArray = (fields[key] as? CborValue.Bytes)?.copyBytes()
                ?: fail(DecisionPayloadFailure.INVALID_BYTES)
            return DecisionPayload(data(1u), data(2u), data(3u), data(4u), data(5u), data(6u), data(7u),
                decodeAction(fields.getValue(8u)))
        }

        private fun decodeAction(value: CborValue): CapturedAction = try {
            ActionWire.decode(value)
        } catch (_: ActionWireException) {
            fail(DecisionPayloadFailure.INVALID_ACTION)
        }

        private fun ensure(condition: Boolean, reason: DecisionPayloadFailure) { if (!condition) fail(reason) }
        private fun fail(reason: DecisionPayloadFailure): Nothing = throw DecisionPayloadException(reason)
    }
}
