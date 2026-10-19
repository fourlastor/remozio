package dev.remozio.protocol

import kotlin.io.encoding.Base64

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
        require(codePoints(label).all { n -> n >= 32 && n !in 127..159 && n !in 0x2028..0x202e &&
            n !in 0x2066..0x2069 && n != 0x200e && n != 0x200f })
        require(minimumEnvelopeVersion > 0uL && !authorityPublicKey.contentEquals(transportPublicKey))
        pairingPoint(authorityPublicKey); pairingPoint(transportPublicKey)
    }
    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to macID, 2uL to accountID, 3uL to CborValue.Text(label),
        4uL to authorityPublicKey, 5uL to transportPublicKey, 6uL to CborValue.Unsigned(minimumEnvelopeVersion),
    )), LIMITS)

    /** QR and pasted text use the same bounded, unpadded base64url payload. This is not a browser URL. */
    fun exportText(): String = PREFIX + BASE64.encode(encode())

    /** Compare through independently authenticated Mac setup. This complete fingerprint does not prove freshness. */
    fun fingerprint(): String {
        val input = DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.pairing.invitation"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Bytes(encode()),
        )), CborLimits(576, 1, 7))
        return sha256(input).toList().chunked(4)
            .joinToString("-") { group -> group.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0').uppercase() } }
    }

    override fun toString() = "PairingInvitation(redacted)"

    companion object {
        private const val PREFIX = "remozio-pairing:v1:"
        private const val MAXIMUM_BYTES = 512
        private const val MAXIMUM_TEXT_CHARACTERS = PREFIX.length + (MAXIMUM_BYTES * 4 + 2) / 3
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 1, 15)
        private val BASE64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
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
            val bytes = BASE64.decode(payload)
            require(bytes.size <= MAXIMUM_BYTES)
            return decode(bytes).also { require(it.exportText() == text) }
        }
    }
}

/** Unicode scalar values; an unpaired surrogate yields its own code unit, as String.codePoints() does. */
internal fun codePoints(text: String): List<Int> {
    val points = ArrayList<Int>(text.length)
    var index = 0
    while (index < text.length) {
        val high = text[index++]
        if (high.isHighSurrogate() && index < text.length && text[index].isLowSurrogate()) {
            val low = text[index++]
            points.add(0x10000 + ((high.code - 0xd800) shl 10) + (low.code - 0xdc00))
        } else {
            points.add(high.code)
        }
    }
    return points
}
