package dev.remozio.protocol

import kotlin.io.encoding.Base64

/** A short-lived invitation from an authenticated setup surface. Treat its serialized bytes as a credential. */
class PairingInvitationV2(
    val invitation: PairingInvitation,
    windowID: ByteArray,
    secret: ByteArray,
    val replacement: PairingReplacement? = null,
    val lifetimeMilliseconds: ULong,
) {
    val windowID = CborValue.Bytes(windowID)
    private val secret = secret.copyOf()

    init {
        require(windowID.size == 16 && secret.size == 32 && lifetimeMilliseconds in 1uL..MAXIMUM_LIFETIME_MILLISECONDS)
    }

    private fun publicFields() = mapOf(
        0uL to CborValue.Unsigned(2u), 1uL to CborValue.Bytes(invitation.encode()), 2uL to windowID,
        4uL to CborValue.Unsigned(if (replacement == null) 0u else 1u),
        5uL to (replacement?.let {
            CborValue.ArrayValue(listOf(invitation.macID, invitation.accountID, it.phoneID, it.epoch))
        } ?: CborValue.Null),
        6uL to CborValue.Unsigned(lifetimeMilliseconds),
    )

    fun encode(): ByteArray = DeterministicCbor.encode(
        CborValue.Fields(publicFields() + (3uL to CborValue.Bytes(secret))), LIMITS,
    )

    fun exportText(): String = PREFIX + BASE64.encode(encode())

    internal fun proofInput(proposal: PairingPhoneProposal, challenge: ByteArray, exporter: ByteArray): ByteArray {
        require(challenge.size == 32 && exporter.size == 32)
        proposal.validateMacScope(invitation)
        require(proposal.replacement?.value() == replacement?.value())
        val publicBytes = DeterministicCbor.encode(CborValue.Fields(publicFields()), LIMITS)
        return DeterministicCbor.encode(CborValue.ArrayValue(listOf(
            CborValue.Text(PROOF_DOMAIN), CborValue.Bytes(sha256(publicBytes)),
            CborValue.Bytes(challenge), CborValue.Bytes(exporter), CborValue.Bytes(sha256(proposal.encode())),
        )), CborLimits(256, 1, 6))
    }

    fun proof(proposal: PairingPhoneProposal, challenge: ByteArray, exporter: ByteArray): ByteArray {
        val input = proofInput(proposal, challenge, exporter)
        val prk = hmacSha256(windowID.copyBytes(), secret)
        try {
            // HKDF-Expand needs one SHA-256 block for the 32-byte output key.
            val key = hmacSha256(prk, KEY_DOMAIN.encodeToByteArray() + byteArrayOf(1))
            try {
                return hmacSha256(key, input)
            } finally {
                key.fill(0)
            }
        } finally {
            prk.fill(0)
        }
    }

    override fun toString() = "PairingInvitationV2(redacted)"

    companion object {
        const val MAXIMUM_BYTES = 768
        const val MAXIMUM_LIFETIME_MILLISECONDS = 300_000uL
        const val EXPORTER_LABEL = "EXPORTER-dev.remozio.pairing.invitation/2"
        private const val PREFIX = "remozio-pairing:v2:"
        private const val MAXIMUM_TEXT_CHARACTERS = PREFIX.length + (MAXIMUM_BYTES * 4 + 2) / 3
        private const val KEY_DOMAIN = "dev.remozio.pairing.invitation-key/2"
        private const val PROOF_DOMAIN = "dev.remozio.pairing.invitation-proof/2"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 2, 24)
        private val BASE64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        fun decode(bytes: ByteArray): PairingInvitationV2 {
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: error("Invalid invitation")
            require(fields.keys == (0uL..6uL).toSet() && fields[0u] == CborValue.Unsigned(2u))
            fun field(key: ULong) = (fields[key] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid invitation")
            val invitation = PairingInvitation.decode(field(1u))
            val predecessor = when (fields[4u]) {
                CborValue.Unsigned(0u) -> {
                    require(fields[5u] == CborValue.Null)
                    null
                }
                CborValue.Unsigned(1u) -> {
                    val scope = (fields[5u] as? CborValue.ArrayValue)?.values ?: error("Invalid predecessor")
                    require(scope.size == 4 && scope[0] == invitation.macID && scope[1] == invitation.accountID)
                    val phone = (scope[2] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid predecessor")
                    val epoch = (scope[3] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid predecessor")
                    PairingReplacement(phone, epoch)
                }
                else -> error("Invalid invitation use")
            }
            val lifetime = (fields[6u] as? CborValue.Unsigned)?.value ?: error("Invalid invitation lifetime")
            return PairingInvitationV2(invitation, field(2u), field(3u), predecessor, lifetime).also {
                require(it.encode().contentEquals(bytes))
            }
        }

        fun importText(text: String): PairingInvitationV2 {
            require(text.length <= MAXIMUM_TEXT_CHARACTERS && text.startsWith(PREFIX))
            val payload = text.drop(PREFIX.length)
            require(payload.isNotEmpty() && payload.length % 4 != 1 && payload.all {
                it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
            })
            return decode(BASE64.decode(payload)).also { require(it.exportText() == text) }
        }
    }
}
