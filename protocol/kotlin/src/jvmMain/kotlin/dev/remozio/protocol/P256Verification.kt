package dev.remozio.protocol

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.Signature
import java.security.SignatureException
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.InvalidKeySpecException

internal object P256Verification {
    fun verify(signature: ByteArray, publicKey: ByteArray, input: ByteArray): Boolean {
        if (signature.size != 64 || publicKey.size != 65) return false
        val pointBytes = publicKey.copyOf()
        val rawSignature = signature.copyOf()
        if (pointBytes[0] != 4.toByte()) return false
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val der = try { P256SignatureEncoding.toDer(rawSignature) }
            catch (_: P256SignatureEncodingException) { return false }
        val x = BigInteger(1, pointBytes.copyOfRange(1, 33))
        val y = BigInteger(1, pointBytes.copyOfRange(33, 65))
        return try {
            val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), parameters))
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(input)
                verify(der)
            }
        } catch (_: InvalidKeySpecException) {
            false
        } catch (_: InvalidKeyException) {
            false
        } catch (_: SignatureException) {
            false
        }
    }
}
