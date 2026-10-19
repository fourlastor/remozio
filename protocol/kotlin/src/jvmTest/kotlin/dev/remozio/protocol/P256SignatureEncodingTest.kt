package dev.remozio.protocol

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class P256SignatureEncodingTest {
    private val order = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun scalar(value: BigInteger) = value.toByteArray().takeLast(32).toByteArray().let {
        ByteArray(32 - it.size) + it
    }

    @Test fun canonicalIntegersHaveMinimalPositiveEncoding() {
        val one = scalar(BigInteger.ONE)
        val cases = mapOf(
            BigInteger.ONE to "3006020101020101",
            BigInteger.valueOf(127) to "300602017f020101",
            BigInteger.valueOf(128) to "300702020080020101",
            BigInteger.valueOf(256) to "300702020100020101",
        )
        for ((value, derHex) in cases) {
            val raw = scalar(value) + one
            assertContentEquals(hex(derHex), P256SignatureEncoding.toDer(raw))
            assertContentEquals(raw, P256SignatureEncoding.fromDer(hex(derHex)))
        }
        for (value in listOf(BigInteger.ONE.shiftLeft(240), BigInteger.ONE.shiftLeft(248),
            BigInteger.ONE.shiftLeft(255), order - BigInteger.ONE)) {
            val raw = scalar(value) + scalar(value)
            assertContentEquals(raw, P256SignatureEncoding.fromDer(P256SignatureEncoding.toDer(raw)))
        }
    }

    @Test fun malformedDerNeverBecomesWireAuthority() {
        val malformed = listOf(
            "3106020101020101", // Wrong sequence tag.
            "3005020101020101", "3007020101020101", // Wrong sequence length.
            "308106020101020101", "30800201010201010000", // Long and indefinite lengths.
            "3006030101020101", "3006020101030101", // Wrong integer tag.
            "3006020180020101", // Negative integer.
            "300702020001020101", // Redundant sign padding.
            "3006020100020101", "3006020101020100", // Zero scalar.
            "30050200020101", // Empty scalar.
            "300702810101020101", // Long integer length.
            "3006022101020101", // Truncated integer.
            "300702010102010100", // Trailing sequence content.
            "300602010102010100", // Trailing bytes outside sequence.
            "3026022100" + order.toString(16) + "020101", // Scalar equals order.
        )
        for (value in malformed) {
            assertFailsWith<P256SignatureEncodingException>(value) { P256SignatureEncoding.fromDer(hex(value)) }
        }
        for (size in listOf(0, 1, 7, 73, 4096)) {
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.fromDer(ByteArray(size)) }
        }
        val valid = hex("3006020101020101")
        for (size in 0 until valid.size) {
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.fromDer(valid.copyOf(size)) }
        }
    }

    @Test fun invalidRawWidthsAndScalarBoundsAreRejected() {
        for (size in listOf(0, 1, 63, 65, 4096)) {
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.toDer(ByteArray(size)) }
        }
        val one = scalar(BigInteger.ONE)
        for (bad in listOf(ByteArray(32), scalar(order), ByteArray(32) { 255.toByte() })) {
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.toDer(bad + one) }
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.toDer(one + bad) }
        }
    }

    @Test fun standardProviderSignaturesVerifyInBothFormatsAndBothSForms() {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        repeat(32) { iteration ->
            val message = "Remozio signature conversion $iteration".toByteArray()
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(key.private); update(message); sign()
            }
            val raw = P256SignatureEncoding.fromDer(der)
            assertContentEquals(der, P256SignatureEncoding.toDer(raw))
            val otherS = order - BigInteger(1, raw.copyOfRange(32, 64))
            for (candidate in listOf(raw, raw.copyOfRange(0, 32) + scalar(otherS))) {
                assertTrue(Signature.getInstance("SHA256withECDSAinP1363Format").run {
                    initVerify(key.public); update(message); verify(candidate)
                })
                assertTrue(Signature.getInstance("SHA256withECDSA").run {
                    initVerify(key.public); update(message); verify(P256SignatureEncoding.toDer(candidate))
                })
            }
        }
    }
}
