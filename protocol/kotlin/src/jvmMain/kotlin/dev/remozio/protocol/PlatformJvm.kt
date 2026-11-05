package dev.remozio.protocol

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Collections

internal actual fun sha256(input: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(input)

internal actual fun pairingPoint(bytes: ByteArray) {
    require(bytes.size == 65 && bytes[0] == 4.toByte())
    val p = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    val b = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    val x = BigInteger(1, bytes.copyOfRange(1, 33)); val y = BigInteger(1, bytes.copyOfRange(33, 65))
    require(x < p && y < p && y.multiply(y).mod(p) == x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(b).mod(p))
}

internal actual fun <T> readOnlySnapshot(values: List<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
internal actual fun <T> readOnlySnapshot(values: Set<T>): Set<T> = Collections.unmodifiableSet(LinkedHashSet(values))
internal actual fun <K, V> readOnlySnapshot(values: Map<K, V>): Map<K, V> = Collections.unmodifiableMap(LinkedHashMap(values))

internal actual fun verifyP256Der(derSignature: ByteArray, publicKey: ByteArray, input: ByteArray): Boolean = try {
    val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
        .getParameterSpec(ECParameterSpec::class.java)
    val x = BigInteger(1, publicKey.copyOfRange(1, 33))
    val y = BigInteger(1, publicKey.copyOfRange(33, 65))
    val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), parameters))
    Signature.getInstance("SHA256withECDSA").run {
        initVerify(key)
        update(input)
        verify(derSignature)
    }
} catch (_: GeneralSecurityException) {
    // Covers a rejected key (InvalidKeySpecException, InvalidKeyException) and a malformed signature.
    false
}
