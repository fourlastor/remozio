package dev.remozio.phone.enrollment

import kotlinx.serialization.json.*

internal fun archiveVector(): JsonObject = Json.parseToJsonElement(TestVectors.enrollmentArchive).jsonObject
internal fun JsonObject.hex(name: String): ByteArray =
    getValue(name).jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/** Keeps the envelope layout. Real AES-GCM belongs to the platform, and the JVM test covers it. */
internal object PlainAead : EnrollmentAead {
    override fun seal(plaintext: ByteArray, associatedData: ByteArray) = ByteArray(12) + plaintext + ByteArray(16)
    override fun open(sealed: ByteArray, associatedData: ByteArray) = sealed.copyOfRange(12, sealed.size - 16)
}

internal class Disk(var bytes: ByteArray?) : EnrollmentStorage {
    var writes = 0
    override fun read(maximumBytes: Int) = bytes?.copyOf()
    override fun replace(ciphertext: ByteArray) { writes++; bytes = ciphertext.copyOf() }
    override fun close() { }
}
