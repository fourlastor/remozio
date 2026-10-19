package dev.remozio.protocol

import java.util.Base64

/** Provider data is an untrusted routing hint. It never authorizes approvals or enrollment changes. */
sealed class PushData {
    class Wake(identifier: ByteArray, enrollmentTag: ByteArray) : PushData() {
        init { require(identifier.size == 32 && enrollmentTag.size == 32) { "Invalid push bytes" } }
        private val id = CborValue.Bytes(identifier)
        private val tag = CborValue.Bytes(enrollmentTag)
        val identifier: ByteArray get() = id.copyBytes()
        val enrollmentTag: ByteArray get() = tag.copyBytes()
        override fun toString(): String = "PushWake(redacted)"
    }
    /** Match this provider-only challenge with retained metadata through the authenticated phone channel. */
    class TokenChallenge(candidateID: ByteArray, challenge: ByteArray, enrollmentTag: ByteArray) : PushData() {
        init { require(candidateID.size == 16 && challenge.size == 32 && enrollmentTag.size == 32) { "Invalid push bytes" } }
        private val candidate = CborValue.Bytes(candidateID)
        private val nonce = CborValue.Bytes(challenge)
        private val tag = CborValue.Bytes(enrollmentTag)
        val candidateID: ByteArray get() = candidate.copyBytes()
        val challenge: ByteArray get() = nonce.copyBytes()
        val enrollmentTag: ByteArray get() = tag.copyBytes()
        override fun toString(): String = "PushTokenChallenge(redacted)"
    }

    fun encode(): Map<String, String> = when (this) {
        is Wake -> mapOf("wake_v1" to text(identifier), "enrollment_v1" to text(enrollmentTag))
        is TokenChallenge -> mapOf("candidate_v1" to text(candidateID), "token_challenge_v1" to text(challenge), "enrollment_v1" to text(enrollmentTag))
    }
    companion object {
        fun decode(data: Map<String, String>): PushData {
            require(data.size in 2..3) { "Invalid push fields" }
            val values = data.toMap()
            return when (values.keys) {
                setOf("wake_v1", "enrollment_v1") -> Wake(bytes(values.getValue("wake_v1"), 32), bytes(values.getValue("enrollment_v1"), 32))
                setOf("candidate_v1", "token_challenge_v1", "enrollment_v1") -> TokenChallenge(bytes(values.getValue("candidate_v1"), 16),
                    bytes(values.getValue("token_challenge_v1"), 32), bytes(values.getValue("enrollment_v1"), 32))
                else -> throw IllegalArgumentException("Invalid push fields")
            }
        }
        private fun text(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
        private fun bytes(value: String, size: Int): ByteArray {
            require(value.length == ((size + 2) / 3) * 4) { "Invalid push encoding" }
            val decoded = try { Base64.getDecoder().decode(value) }
            catch (_: IllegalArgumentException) { throw IllegalArgumentException("Invalid push encoding") }
            require(decoded.size == size && text(decoded) == value) { "Invalid push encoding" }
            return decoded
        }
    }
}
