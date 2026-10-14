package dev.remozio.protocol

import java.math.BigInteger
import java.security.MessageDigest

/** Public setup material only. Local aliases and credentials never belong in this transcript. */
class PairingKey(keyID: ByteArray, publicKey: ByteArray) {
    val keyID = CborValue.Bytes(keyID)
    val publicKey = CborValue.Bytes(publicKey)
    init { require(keyID.size == 16); pairingPoint(publicKey) }
    internal fun value() = CborValue.ArrayValue(listOf(keyID, publicKey))
    override fun toString() = "PairingKey(redacted)"
}

class PairingReplacement(phoneID: ByteArray, epoch: ByteArray) {
    val phoneID = CborValue.Bytes(phoneID)
    val epoch = CborValue.Bytes(epoch)
    init { require(phoneID.size == 16 && epoch.size == 16) }
    internal fun value() = CborValue.ArrayValue(listOf(phoneID, epoch))
    override fun toString() = "PairingReplacement(redacted)"
}

enum class PairingProofPurpose(val tag: ULong) { PHONE_BIOMETRIC(0u), MAC_COMMIT(1u) }

/** Untrusted setup claims. Parsing or signature verification does not authorize enrollment. */
class PairingTranscript(
    setupID: ByteArray, challenge: ByteArray, val phone: ChannelOffer, val mac: ChannelOffer,
    val minimumEnvelopeVersion: ULong, val selectedEnvelopeVersion: ULong,
    macAuthorityKey: ByteArray, macTransportKey: ByteArray,
    val transportKey: PairingKey, val decisionKey: PairingKey, val biometricKey: PairingKey,
    enrollmentTag: ByteArray, val replacement: PairingReplacement?, expectedTrustRevision: ByteArray,
    val issuedAtUnixMillis: ULong, val expiresAtUnixMillis: ULong,
) {
    val expectedTrustRevision = CborValue.Bytes(expectedTrustRevision)
    val setupID = CborValue.Bytes(setupID)
    val challenge = CborValue.Bytes(challenge)
    val macAuthorityKey = CborValue.Bytes(macAuthorityKey)
    val macTransportKey = CborValue.Bytes(macTransportKey)
    val enrollmentTag = CborValue.Bytes(enrollmentTag)
    init {
        require(setupID.size == 16 && challenge.size == 32 && enrollmentTag.size == 32 && expectedTrustRevision.size == 16)
        require(phone.role == ChannelRole.PHONE && mac.role == ChannelRole.MAC && phone.scope == mac.scope && phone.nonce != mac.nonce)
        require(minimumEnvelopeVersion > 0uL && selectedEnvelopeVersion ==
            CompatibilityPolicy.envelopeVersion(phone.envelopeVersions, mac.envelopeVersions, minimumEnvelopeVersion))
        require(expiresAtUnixMillis > issuedAtUnixMillis)
        pairingPoint(macAuthorityKey); pairingPoint(macTransportKey)
        val keys = listOf(transportKey, decisionKey, biometricKey)
        require(keys.map { it.keyID }.toSet().size == 3)
        require((keys.map { it.publicKey } + listOf(this.macAuthorityKey, this.macTransportKey)).toSet().size == 5)
        replacement?.let {
            require(it.epoch != (phone.scope.value.values[3] as CborValue.Bytes))
        }
    }
    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to setupID, 2uL to challenge,
        3uL to CborValue.Bytes(phone.encode()), 4uL to CborValue.Bytes(mac.encode()),
        5uL to CborValue.Unsigned(minimumEnvelopeVersion), 6uL to CborValue.Unsigned(selectedEnvelopeVersion),
        7uL to macAuthorityKey, 8uL to macTransportKey,
        9uL to CborValue.ArrayValue(listOf(transportKey, decisionKey, biometricKey).map { it.value() }),
        10uL to enrollmentTag, 11uL to (replacement?.value() ?: CborValue.Null),
        12uL to expectedTrustRevision, 13uL to CborValue.Unsigned(issuedAtUnixMillis),
        14uL to CborValue.Unsigned(expiresAtUnixMillis),
    )), LIMITS)
    fun digest(): ByteArray = MessageDigest.getInstance("SHA-256").digest(signingInput(PairingProofPurpose.PHONE_BIOMETRIC))
    fun signingInput(purpose: PairingProofPurpose): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Text("dev.remozio.pairing"), 1uL to CborValue.Unsigned(1u),
        2uL to CborValue.Unsigned(purpose.tag), 3uL to CborValue.Bytes(encode()),
    )), CborLimits(132_096, 3, 16))
    fun verify(signature: ByteArray, publicKey: ByteArray, purpose: PairingProofPurpose): Boolean =
        P256Verification.verify(signature, publicKey, signingInput(purpose))
    override fun toString() = "PairingTranscript(redacted)"

    companion object {
        private val LIMITS = CborLimits(132_000, 4, 80)
        fun decode(bytes: ByteArray): PairingTranscript {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: error("Invalid pairing")
            require(f.keys == (0uL..14uL).toSet() && f[0u] == CborValue.Unsigned(1u))
            fun b(k: ULong) = (f[k] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid pairing")
            fun u(k: ULong) = (f[k] as? CborValue.Unsigned)?.value ?: error("Invalid pairing")
            val keys = (f[9u] as? CborValue.ArrayValue)?.values ?: error("Invalid pairing")
            require(keys.size == 3)
            fun pair(value: CborValue): List<ByteArray> {
                val row = (value as? CborValue.ArrayValue)?.values ?: error("Invalid pairing")
                require(row.size == 2)
                return row.map { (it as? CborValue.Bytes)?.copyBytes() ?: error("Invalid pairing") }
            }
            fun key(i: Int) = pair(keys[i]).let { PairingKey(it[0], it[1]) }
            val replacement = if (f[11u] == CborValue.Null) null else pair(f.getValue(11u)).let { PairingReplacement(it[0], it[1]) }
            return PairingTranscript(b(1u), b(2u), ChannelOffer.decode(b(3u)), ChannelOffer.decode(b(4u)), u(5u), u(6u),
                b(7u), b(8u), key(0), key(1), key(2), b(10u), replacement, b(12u), u(13u), u(14u)).also {
                require(it.encode().contentEquals(bytes))
            }
        }
    }
}

internal fun pairingPoint(bytes: ByteArray) {
    require(bytes.size == 65 && bytes[0] == 4.toByte())
    val p = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    val b = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    val x = BigInteger(1, bytes.copyOfRange(1, 33)); val y = BigInteger(1, bytes.copyOfRange(33, 65))
    require(x < p && y < p && y.multiply(y).mod(p) == x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(b).mod(p))
}
