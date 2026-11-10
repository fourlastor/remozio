package dev.remozio.phone.enrollment

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** AES-GCM with a dedicated hardware key. The provider chooses each nonce. */
private class JavaEnrollmentAead(private val key: SecretKey) : EnrollmentAead {
    override fun seal(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        require(cipher.iv.size == 12 && cipher.parameters.getParameterSpec(GCMParameterSpec::class.java).tLen == 128)
        cipher.updateAAD(associatedData)
        return cipher.iv + cipher.doFinal(plaintext)
    }

    override fun open(sealed: ByteArray, associatedData: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
        cipher.updateAAD(associatedData)
        return cipher.doFinal(sealed, 12, sealed.size - 12)
    }
}

fun EnrollmentCipher(key: SecretKey, maximumPlaintextBytes: Int): EnrollmentCipher =
    EnrollmentCipher(JavaEnrollmentAead(key), maximumPlaintextBytes)
