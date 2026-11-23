package dev.remozio.protocol

import kotlin.io.encoding.Base64

/** An unsigned selection for an existing enrollment. Only the setup transcript authorizes pairing. */
class RePairInvitation(val invitation: PairingInvitation, val predecessor: PairingReplacement) {
    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.ArrayValue(listOf(
        CborValue.Unsigned(1u), CborValue.Bytes(invitation.encode()), CborValue.ArrayValue(listOf(
            invitation.macID, invitation.accountID, predecessor.phoneID, predecessor.epoch)),
    )), LIMITS)

    fun exportText(): String = PREFIX + BASE64.encode(encode())

    override fun toString() = "RePairInvitation(redacted)"

    companion object {
        private const val PREFIX = "remozio-repair:v1:"
        private const val MAXIMUM_BYTES = 640
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 2, 12)
        private val BASE64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        fun decode(bytes: ByteArray): RePairInvitation {
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.ArrayValue)?.values
                ?: error("Invalid re-pair invitation")
            require(fields.size == 3 && fields[0] == CborValue.Unsigned(1u))
            val ordinary = (fields[1] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid invitation")
            val scope = (fields[2] as? CborValue.ArrayValue)?.values ?: error("Invalid predecessor")
            require(scope.size == 4)
            val invitation = PairingInvitation.decode(ordinary)
            require(scope[0] == invitation.macID && scope[1] == invitation.accountID)
            val phoneID = (scope[2] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid phone ID")
            val epoch = (scope[3] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid enrollment epoch")
            return RePairInvitation(invitation, PairingReplacement(phoneID, epoch)).also {
                require(it.encode().contentEquals(bytes))
            }
        }

        fun importText(text: String): RePairInvitation {
            require(text.length <= PREFIX.length + (MAXIMUM_BYTES * 4 + 2) / 3 && text.startsWith(PREFIX))
            val payload = text.substring(PREFIX.length)
            require(payload.isNotEmpty() && payload.length % 4 != 1 && payload.all {
                it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
            })
            return decode(BASE64.decode(payload)).also { require(it.exportText() == text) }
        }
    }
}
