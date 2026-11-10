package dev.remozio.phone.enrollment

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.*
import org.junit.Test
import kotlin.test.*

/** Real AES-GCM against the archive that the JVM-only store wrote before the move. */
class EnrollmentCipherJvmTest {
    private val vector = Json.parseToJsonElement(TestVectors.enrollmentArchive).jsonObject
    private fun hex(name: String) = vector.getValue(name).jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val maximumBytes = vector.getValue("maximumPlaintextBytes").jsonPrimitive.int
    private val key = SecretKeySpec(hex("aesKey"), "AES")
    private val cipher = EnrollmentCipher(key, maximumBytes)

    @Test fun readsTheArchiveWrittenBeforeTheMove() {
        assertContentEquals(hex("plaintextSchema2"), cipher.decrypt(hex("encryptedArchive")))
        val storage = object : EnrollmentStorage {
            override fun read(maximumBytes: Int) = hex("encryptedArchive")
            override fun replace(ciphertext: ByteArray) = error("A read must not write")
            override fun close() { }
        }
        assertEquals(3, EncryptedEnrollmentStore.open(storage, cipher, 10).snapshot().entries.size)
    }

    @Test fun writesTheMagicTheNonceTheCiphertextAndTheTag() {
        val plaintext = hex("plaintextSchema1")
        val sealed = cipher.encrypt(plaintext)
        assertEquals(plaintext.size + 36, sealed.size)
        assertContentEquals("RMZENR01".encodeToByteArray(), sealed.copyOfRange(0, 8))
        val plain = Cipher.getInstance("AES/GCM/NoPadding")
        plain.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(8, 20)))
        plain.updateAAD("dev.remozio.phone.enrollments/v1".encodeToByteArray())
        assertContentEquals(plaintext, plain.doFinal(sealed, 20, sealed.size - 20))
    }

    @Test fun refusesATamperedArchiveAndAnotherKey() {
        val archive = hex("encryptedArchive")
        assertFails { cipher.decrypt(archive.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }) }
        assertFails { EnrollmentCipher(SecretKeySpec(ByteArray(32), "AES"), maximumBytes).decrypt(archive) }
    }

    @Test fun aTamperedArchiveIsRefusedAndNeverRewritten() {
        val archive = hex("encryptedArchive").also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        val storage = object : EnrollmentStorage {
            override fun read(maximumBytes: Int) = archive
            override fun replace(ciphertext: ByteArray) = error("A refused archive must not be rewritten")
            override fun close() { }
        }
        assertFailsWith<EnrollmentStoreUnavailable> { EncryptedEnrollmentStore.open(storage, cipher, 10) }
    }

    @Test fun activationStaysHiddenFromJava() {
        val activate = EncryptedEnrollmentStore::class.java.declaredMethods
            .single { it.name.startsWith("activate") && !it.name.endsWith("\$default") }
        assertTrue(activate.isSynthetic)
    }

    @Test fun eachEncryptionUsesAFreshNonce() {
        assertFalse(cipher.encrypt(ByteArray(8)).copyOfRange(8, 20).contentEquals(cipher.encrypt(ByteArray(8)).copyOfRange(8, 20)))
    }
}
