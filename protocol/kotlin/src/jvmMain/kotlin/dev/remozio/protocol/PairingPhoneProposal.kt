package dev.remozio.protocol

/** Public phone claims only. A proposal grants no enrollment or request authority. */
class PairingPhoneProposal(val phone: ChannelOffer, val transportKey: PairingKey,
    val decisionKey: PairingKey, val biometricKey: PairingKey,
) {
    init {
        require(phone.role == ChannelRole.PHONE)
        val keys = listOf(transportKey, decisionKey, biometricKey)
        require(keys.map { it.keyID }.toSet().size == 3 && keys.map { it.publicKey }.toSet().size == 3)
    }
    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Text("dev.remozio.pairing.proposal"), 1uL to CborValue.Unsigned(1u),
        2uL to CborValue.Bytes(phone.encode()), 3uL to CborValue.ArrayValue(
            listOf(transportKey, decisionKey, biometricKey).map { it.value() }),
    )), LIMITS)
    fun validateMacScope(invitation: PairingInvitation) {
        require(phone.scope.value.values.take(2) == listOf(invitation.macID, invitation.accountID))
        require(listOf(transportKey.publicKey, decisionKey.publicKey, biometricKey.publicKey)
            .none { it == invitation.authorityPublicKey || it == invitation.transportPublicKey })
    }
    fun validate(transcript: PairingTranscript) {
        require(transcript.replacement == null && transcript.phone.encode().contentEquals(phone.encode()))
        listOf(transportKey, decisionKey, biometricKey).zip(listOf(transcript.transportKey, transcript.decisionKey, transcript.biometricKey))
            .forEach { (expected, actual) -> require(expected.keyID == actual.keyID && expected.publicKey == actual.publicKey) }
    }
    override fun toString() = "PairingPhoneProposal(redacted)"
    companion object {
        private val LIMITS = CborLimits(66_000, 3, 24)
        fun decode(bytes: ByteArray): PairingPhoneProposal {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: error("Invalid proposal")
            require(f.keys == (0uL..3uL).toSet() && f[0u] == CborValue.Text("dev.remozio.pairing.proposal") && f[1u] == CborValue.Unsigned(1u))
            val phone = (f[2u] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid proposal")
            val keys = (f[3u] as? CborValue.ArrayValue)?.values ?: error("Invalid proposal")
            require(keys.size == 3)
            fun key(i: Int): PairingKey {
                val row = (keys[i] as? CborValue.ArrayValue)?.values ?: error("Invalid proposal")
                require(row.size == 2)
                return PairingKey((row[0] as CborValue.Bytes).copyBytes(), (row[1] as CborValue.Bytes).copyBytes())
            }
            return PairingPhoneProposal(ChannelOffer.decode(phone), key(0), key(1), key(2)).also { require(it.encode().contentEquals(bytes)) }
        }
    }
}
