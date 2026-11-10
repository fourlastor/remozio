package dev.remozio.phone.transport

import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec

internal actual fun p256TransportPin(encoded: ByteArray): ByteArray {
    require(encoded.size in 1..256) { "Invalid transport pin" }
    val copy = encoded.copyOf()
    val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(copy)) as? ECPublicKey
        ?: throw IllegalArgumentException("P-256 transport key required")
    val curve = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
        .getParameterSpec(ECParameterSpec::class.java)
    require(key.params.curve == curve.curve && key.params.generator == curve.generator &&
        key.params.order == curve.order && key.params.cofactor == curve.cofactor && key.encoded.contentEquals(copy))
    return copy
}
