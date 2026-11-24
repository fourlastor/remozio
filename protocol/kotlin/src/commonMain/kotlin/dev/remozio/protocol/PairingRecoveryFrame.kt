package dev.remozio.protocol

/** The candidate presents one exact transcript on the dedicated recovery connection. */
class PairingRecoveryQuery(
    setupID: ByteArray,
    transcriptDigest: ByteArray,
    val scope: ChannelScope,
) {
    val setupID = CborValue.Bytes(setupID)
    val transcriptDigest = CborValue.Bytes(transcriptDigest)

    init { require(this.setupID.size == 16 && this.transcriptDigest.size == 32) }

    internal fun body(): ByteArray = ByteArray(112).also { body ->
        setupID.copyBytes().copyInto(body)
        transcriptDigest.copyBytes().copyInto(body, 16)
        scope.value.values.forEachIndexed { index, field ->
            (field as CborValue.Bytes).copyBytes().copyInto(body, 48 + index * 16)
        }
    }

    fun signingInput(exporter: ByteArray, challenge: ByteArray): ByteArray {
        require(exporter.size == 32 && challenge.size == 32)
        return "dev.remozio.pairing.recovery-lookup/1".encodeToByteArray() + byteArrayOf(0) + exporter + challenge + body()
    }

    override fun toString() = "PairingRecoveryQuery(redacted)"

    companion object {
        fun fromTranscript(transcript: PairingTranscript): PairingRecoveryQuery {
            require(transcript.replacement != null)
            return PairingRecoveryQuery(transcript.setupID.copyBytes(), transcript.digest(), transcript.phone.scope)
        }

        internal fun decode(body: ByteArray): PairingRecoveryQuery {
            require(body.size == 112)
            return PairingRecoveryQuery(body.copyOfRange(0, 16), body.copyOfRange(16, 48), ChannelScope(
                body.copyOfRange(48, 64), body.copyOfRange(64, 80), body.copyOfRange(80, 96), body.copyOfRange(96, 112),
            ))
        }
    }
}

/** A four-frame exchange over authenticated TLS. The frame excludes its length prefix. */
sealed class PairingRecoveryFrame {
    class Lookup(val query: PairingRecoveryQuery) : PairingRecoveryFrame()
    class Challenge(bytes: ByteArray) : PairingRecoveryFrame() {
        val bytes = CborValue.Bytes(bytes)
        init { require(this.bytes.size == 32) }
    }
    class Proof(signature: ByteArray) : PairingRecoveryFrame() {
        val signature = CborValue.Bytes(signature)
        init { require(this.signature.size == 64) }
    }

    sealed class Reply : PairingRecoveryFrame()
    data object Refused : Reply()
    class Committed(signature: ByteArray) : Reply() {
        val signature = CborValue.Bytes(signature)
        init { require(this.signature.size == 64) }
    }
    class Expired(val receipt: PairingExpiryReceipt) : Reply()

    fun encode(): ByteArray = when (this) {
        is Lookup -> byteArrayOf(0) + query.body()
        is Challenge -> byteArrayOf(1) + bytes.copyBytes()
        is Proof -> byteArrayOf(2) + signature.copyBytes()
        Refused -> byteArrayOf(3)
        is Committed -> byteArrayOf(4) + signature.copyBytes()
        is Expired -> byteArrayOf(5) + receipt.encode()
    }

    final override fun toString() = "PairingRecoveryFrame(redacted)"

    companion object {
        const val APPLICATION_PROTOCOL = "remozio-pairing-recovery/1"
        const val EXPORTER_LABEL = "EXPORTER-dev.remozio.pairing.recovery-lookup/1"
        const val MAXIMUM_BYTES = 1 + PairingExpiryReceipt.MAXIMUM_BYTES

        fun decode(bytes: ByteArray): PairingRecoveryFrame {
            require(bytes.size in 1..MAXIMUM_BYTES)
            val body = bytes.copyOfRange(1, bytes.size)
            return when (bytes[0].toInt()) {
                0 -> Lookup(PairingRecoveryQuery.decode(body))
                1 -> Challenge(body)
                2 -> Proof(body)
                3 -> { require(body.isEmpty()); Refused }
                4 -> Committed(body)
                5 -> Expired(PairingExpiryReceipt.decode(body))
                else -> throw IllegalArgumentException("Invalid pairing recovery frame")
            }
        }
    }
}
