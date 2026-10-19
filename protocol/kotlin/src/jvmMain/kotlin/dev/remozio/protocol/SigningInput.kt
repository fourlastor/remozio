package dev.remozio.protocol

enum class ApprovalMessageType(val tag: ULong) { REQUEST(1u), DECISION(2u), STATUS(3u) }
enum class SigningPurpose(val tag: ULong) {
    ISSUED_REQUEST(1u), CANCELLATION(2u), ONE_TIME_UI(3u), BIOMETRIC_AUTHORIZATION(4u), STATUS(5u),
}

enum class SigningInputFailure { UNSUPPORTED_VERSION, INCOMPATIBLE_PURPOSE, PAYLOAD_MUST_BE_MAP }
class SigningInputException(val reason: SigningInputFailure) : IllegalArgumentException(reason.name)

/** Constructs signature input only. Verification must use the context expected by retained state. */
object SigningInput {
    fun make(
        wireVersion: ULong,
        messageType: ApprovalMessageType,
        purpose: SigningPurpose,
        canonicalPayload: ByteArray,
        payloadLimits: CborLimits,
        inputLimits: CborLimits,
    ): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        val compatible = when (messageType) {
            ApprovalMessageType.REQUEST -> purpose == SigningPurpose.ISSUED_REQUEST
            ApprovalMessageType.DECISION -> purpose == SigningPurpose.CANCELLATION ||
                purpose == SigningPurpose.ONE_TIME_UI || purpose == SigningPurpose.BIOMETRIC_AUTHORIZATION
            ApprovalMessageType.STATUS -> purpose == SigningPurpose.STATUS
        }
        if (!compatible) throw SigningInputException(SigningInputFailure.INCOMPATIBLE_PURPOSE)
        if (canonicalPayload.size > payloadLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        val payload = canonicalPayload.copyOf()
        if (DeterministicCbor.decode(payload, payloadLimits) !is CborValue.Fields) {
            throw SigningInputException(SigningInputFailure.PAYLOAD_MUST_BE_MAP)
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.approval"),
            1uL to CborValue.Unsigned(wireVersion),
            2uL to CborValue.Unsigned(messageType.tag),
            3uL to CborValue.Unsigned(purpose.tag),
            4uL to CborValue.Bytes(payload),
        )), inputLimits)
    }
}
