package dev.remozio.protocol

import kotlin.test.*

class ApprovalMessageTest {
    private val limits = CborLimits(256, 2, 20)
    @Test fun exactOpaqueBytesAndSignatureUseTheSharedWireEncoding() {
        val body = byteArrayOf(1, 2, 3)
        val signature = ByteArray(64) { 0xaa.toByte() }
        val message = ApprovalMessage(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, body, signature)
        body.fill(0); signature.fill(0)
        val encoded = message.encode(3)
        assertEquals("a600010101020103010443010203055840" + "aa".repeat(64), encoded.joinToString("") { "%02x".format(it) })
        val decoded = ApprovalMessage.decode(encoded, 3)
        assertEquals(message.body, decoded.body); assertEquals(message.signature, decoded.signature)
        assertEquals("ApprovalMessage(redacted)", decoded.toString())
    }
    @Test fun onlyDefinedSigningDomainsAndWireVersionsAreCarried() {
        for (type in ApprovalMessageType.entries) for (purpose in SigningPurpose.entries) {
            val valid = when (type) {
                ApprovalMessageType.REQUEST -> purpose == SigningPurpose.ISSUED_REQUEST
                ApprovalMessageType.STATUS -> purpose == SigningPurpose.STATUS
                ApprovalMessageType.DECISION -> purpose in setOf(SigningPurpose.CANCELLATION, SigningPurpose.ONE_TIME_UI, SigningPurpose.BIOMETRIC_AUTHORIZATION)
            }
            val result = runCatching { ApprovalMessage(1u, type, purpose, byteArrayOf(1), ByteArray(64)).encode(1) }
            assertEquals(valid, result.isSuccess)
        }
        assertFails { ApprovalMessage(2u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, byteArrayOf(1), ByteArray(64)) }
    }
    @Test fun malformedUnsupportedAndOversizedCarriersFail() {
        val message = ApprovalMessage(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, byteArrayOf(1), ByteArray(64))
        val encoded = message.encode(1)
        val fields = (DeterministicCbor.decode(encoded, limits) as CborValue.Fields).values
        for (change in listOf(0uL to CborValue.Unsigned(2u), 1uL to CborValue.Unsigned(2u),
            2uL to CborValue.Unsigned(99u), 3uL to CborValue.Unsigned(99u), 3uL to CborValue.Unsigned(5u),
            4uL to CborValue.Bytes(ByteArray(0)), 4uL to CborValue.Bytes(ByteArray(2)), 5uL to CborValue.Bytes(ByteArray(63)),
            6uL to CborValue.Unsigned(1u))) {
            assertFails { ApprovalMessage.decode(DeterministicCbor.encode(CborValue.Fields(fields + change), limits), 1) }
        }
        assertFails { ApprovalMessage.decode(encoded + byteArrayOf(0), 1) }
        assertFails { ApprovalMessage.decode(encoded, Int.MAX_VALUE) }
        assertFails { message.encode(0) }
    }
}
