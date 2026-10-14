package dev.remozio.protocol

import java.security.MessageDigest
import java.util.Base64

/** Public bootstrap pins. Importing these claims does not authenticate the Mac or authorize enrollment. */
class PairingInvitation(macID: ByteArray, accountID: ByteArray, val label: String,
    authorityPublicKey: ByteArray, transportPublicKey: ByteArray, val minimumEnvelopeVersion: ULong,
) {
    val macID = CborValue.Bytes(macID)
    val accountID = CborValue.Bytes(accountID)
    val authorityPublicKey = CborValue.Bytes(authorityPublicKey)
    val transportPublicKey = CborValue.Bytes(transportPublicKey)
    init {
        require(macID.size == 16 && accountID.size == 16)
        require(label.encodeToByteArray(throwOnInvalidSequence = true).size in 1..200 && label.any { it != ' ' })
        require(label.codePoints().allMatch { n -> n >= 32 && n !in 127..159 && n !in 0x2028..0x202e &&
            n !in 0x2066..0x2069 && n != 0x200e && n != 0x200f })
        require(minimumEnvelopeVersion > 0uL && !authorityPublicKey.contentEquals(transportPublicKey))
        pairingPoint(authorityPublicKey); pairingPoint(transportPublicKey)
    }
    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to macID, 2uL to accountID, 3uL to CborValue.Text(label),
        4uL to authorityPublicKey, 5uL to transportPublicKey, 6uL to CborValue.Unsigned(minimumEnvelopeVersion),
    )), LIMITS)

    /** QR and pasted text use the same bounded, unpadded base64url payload. This is not a browser URL. */
    fun exportText(): String = PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(encode())

    /** Compare through independently authenticated Mac setup. This complete fingerprint does not prove freshness. */
    fun fingerprint(): String {
        val input = DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.pairing.invitation"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Bytes(encode()),
        )), CborLimits(576, 1, 7))
        return MessageDigest.getInstance("SHA-256").digest(input).toList().chunked(4)
            .joinToString("-") { group -> group.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0').uppercase() } }
    }

    /** Consistency only. The host must still verify the complete fresh transcript and peer identity. */
    fun validateMacClaims(transcript: PairingTranscript) {
        require(transcript.phone.scope.value.values.take(2) == listOf(macID, accountID))
        require(transcript.macAuthorityKey == authorityPublicKey && transcript.macTransportKey == transportPublicKey)
        require(transcript.minimumEnvelopeVersion == minimumEnvelopeVersion)
    }
    override fun toString() = "PairingInvitation(redacted)"

    companion object {
        private const val PREFIX = "remozio-pairing:v1:"
        private const val MAXIMUM_BYTES = 512
        private const val MAXIMUM_TEXT_CHARACTERS = PREFIX.length + (MAXIMUM_BYTES * 4 + 2) / 3
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 1, 15)
        fun decode(bytes: ByteArray): PairingInvitation {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: error("Invalid invitation")
            require(f.keys == (0uL..6uL).toSet() && f[0u] == CborValue.Unsigned(1u))
            fun b(k: ULong) = (f[k] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid invitation")
            val label = (f[3u] as? CborValue.Text)?.value ?: error("Invalid invitation")
            val minimum = (f[6u] as? CborValue.Unsigned)?.value ?: error("Invalid invitation")
            return PairingInvitation(b(1u), b(2u), label, b(4u), b(5u), minimum).also {
                require(it.encode().contentEquals(bytes))
            }
        }
        fun importText(text: String): PairingInvitation {
            require(text.length <= MAXIMUM_TEXT_CHARACTERS && text.startsWith(PREFIX))
            val payload = text.substring(PREFIX.length)
            require(payload.isNotEmpty() && payload.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' })
            require(payload.length % 4 != 1)
            val bytes = Base64.getUrlDecoder().decode(payload)
            require(bytes.size <= MAXIMUM_BYTES)
            return decode(bytes).also { require(it.exportText() == text) }
        }
    }
}
