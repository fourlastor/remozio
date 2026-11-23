package dev.remozio.protocol

/** Public phone claims only. A proposal grants no enrollment or request authority. */
class PairingPhoneProposal(val phone: ChannelOffer, val transportKey: PairingKey,
    val decisionKey: PairingKey, val biometricKey: PairingKey,
    val replacement: PairingReplacement? = null,
) {
    init {
        require(phone.role == ChannelRole.PHONE)
        replacement?.let {
            require(it.phoneID == phone.scope.value.values[2] && it.epoch != phone.scope.value.values[3])
        }
        val keys = listOf(transportKey, decisionKey, biometricKey)
        require(keys.map { it.keyID }.toSet().size == 3 && keys.map { it.publicKey }.toSet().size == 3)
    }
    fun encode(): ByteArray {
        val fields = mutableMapOf<ULong, CborValue>(
            0uL to CborValue.Text("dev.remozio.pairing.proposal"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Bytes(phone.encode()),
            3uL to CborValue.ArrayValue(listOf(transportKey, decisionKey, biometricKey).map { it.value() }),
        )
        replacement?.let {
            fields[1u] = CborValue.Unsigned(2u)
            fields[4u] = it.value()
        }
        return DeterministicCbor.encode(CborValue.Fields(fields), LIMITS)
    }
    fun validateMacScope(invitation: PairingInvitation) {
        require(phone.scope.value.values.take(2) == listOf(invitation.macID, invitation.accountID))
        require(listOf(transportKey.publicKey, decisionKey.publicKey, biometricKey.publicKey)
            .none { it == invitation.authorityPublicKey || it == invitation.transportPublicKey })
    }
    fun validate(transcript: PairingTranscript) {
        require(transcript.replacement?.value() == replacement?.value() && transcript.phone.encode().contentEquals(phone.encode()))
        listOf(transportKey, decisionKey, biometricKey).zip(listOf(transcript.transportKey, transcript.decisionKey, transcript.biometricKey))
            .forEach { (expected, actual) -> require(expected.keyID == actual.keyID && expected.publicKey == actual.publicKey) }
    }
    override fun toString() = "PairingPhoneProposal(redacted)"
    companion object {
        private val LIMITS = CborLimits(66_000, 3, 24)
        fun decode(bytes: ByteArray): PairingPhoneProposal {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: error("Invalid proposal")
            require(f[0u] == CborValue.Text("dev.remozio.pairing.proposal"))
            val replacement = when (f[1u]) {
                CborValue.Unsigned(1u) -> {
                    require(f.keys == (0uL..3uL).toSet())
                    null
                }
                CborValue.Unsigned(2u) -> {
                    require(f.keys == (0uL..4uL).toSet())
                    val row = (f[4u] as? CborValue.ArrayValue)?.values ?: error("Invalid replacement")
                    require(row.size == 2)
                    PairingReplacement((row[0] as CborValue.Bytes).copyBytes(), (row[1] as CborValue.Bytes).copyBytes())
                }
                else -> error("Invalid proposal version")
            }
            val phone = (f[2u] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid proposal")
            val keys = (f[3u] as? CborValue.ArrayValue)?.values ?: error("Invalid proposal")
            require(keys.size == 3)
            fun key(i: Int): PairingKey {
                val row = (keys[i] as? CborValue.ArrayValue)?.values ?: error("Invalid proposal")
                require(row.size == 2)
                return PairingKey((row[0] as CborValue.Bytes).copyBytes(), (row[1] as CborValue.Bytes).copyBytes())
            }
            return PairingPhoneProposal(ChannelOffer.decode(phone), key(0), key(1), key(2), replacement).also { require(it.encode().contentEquals(bytes)) }
        }
    }
}
