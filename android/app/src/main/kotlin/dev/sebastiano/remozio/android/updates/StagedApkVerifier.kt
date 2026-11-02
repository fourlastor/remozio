package dev.sebastiano.remozio.android.updates

import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

internal data class ApkExpectation(val versionName: String, val size: Long)

/** Own one verifier per update host. It permits one staged APK until its handle is closed. */
internal class StagedApkVerifier(
    private val privateCache: File,
    private val inspector: ApkInspector,
    private val deviceSdk: Int,
    private val maxBytes: Long = 256L * 1024 * 1024,
) {
    init { require(maxBytes in 1..Int.MAX_VALUE.toLong()) }
    private val occupied = AtomicBoolean()

    /** Takes ownership of [source], including on rejection or cancellation. */
    suspend fun stage(source: InputStream, expectation: ApkExpectation? = null): VerifiedApk {
        var result: VerifiedApk? = null
        try {
            return withContext(Dispatchers.IO) {
                source.use {
                    if (!occupied.compareAndSet(false, true)) throw UpdateRejected()
                    var directory: File? = null
                    try {
                        coroutineContext.ensureActive()
                        directory = Files.createTempDirectory(privateCache.toPath(), "remozio-update-").toFile()
                        val file = File(directory, "update.apk")
                        val digest = MessageDigest.getInstance("SHA-256")
                        val size = file.outputStream().use { output ->
                            copyBounded(source, output, maxBytes, digest) { coroutineContext.ensureActive() }
                        }
                        if (size == 0L || !file.setReadOnly()) throw UpdateRejected()
                        val expected = digest.digest()
                        val candidate = inspector.verify(file)
                        checkUpdate(inspector.installed(), candidate, deviceSdk)
                        if (expectation != null && (candidate.versionName != expectation.versionName || size != expectation.size)) throw UpdateRejected()
                        file.inputStream().use { input ->
                            val checked = MessageDigest.getInstance("SHA-256")
                            copyBounded(input, OutputStream.nullOutputStream(), maxBytes, checked) {
                                coroutineContext.ensureActive()
                            }
                            if (!MessageDigest.isEqual(expected, checked.digest())) throw UpdateRejected()
                        }
                        VerifiedApk(directory, file, candidate, size, expected) { occupied.set(false) }
                            .also { result = it }
                    } catch (error: Throwable) {
                        if (directory == null || removeStage(directory)) occupied.set(false)
                        throw error
                    }
                }
            }
        } catch (cancelled: CancellationException) {
            runCatching { result?.close() }
            throw cancelled
        } catch (_: Exception) {
            result?.close()
            throw UpdateRejected()
        } finally {
            // Also covers cancellation before the IO dispatcher enters source.use.
            runCatching { source.close() }
        }
    }
}

internal class VerifiedApk internal constructor(
    private val directory: File,
    private val file: File,
    val identity: ApkIdentity,
    val size: Long,
    private val sha256: ByteArray,
    private val release: () -> Unit,
) : AutoCloseable {
    private var closed = false

    /** Write only to an uncommitted installer session. Discard that session if this method fails. */
    @Synchronized fun copyToUncommittedSession(output: OutputStream) {
        if (closed) throw UpdateRejected()
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val copied = file.inputStream().use { copyBounded(it, output, size, digest) {} }
            if (copied != size || !MessageDigest.isEqual(sha256, digest.digest())) throw UpdateRejected()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            throw UpdateRejected()
        }
    }

    @Synchronized override fun close() {
        if (closed) return
        if (!removeStage(directory)) throw UpdateRejected()
        closed = true
        release()
    }
}

private fun copyBounded(input: InputStream, output: OutputStream, limit: Long,
    digest: MessageDigest, checkActive: () -> Unit): Long {
    val buffer = ByteArray(16 * 1024)
    var total = 0L
    while (true) {
        checkActive()
        val count = input.read(buffer, 0, minOf(buffer.size.toLong(), limit - total + 1).toInt())
        if (count < 0) return total
        if (count == 0) throw UpdateRejected()
        total += count
        if (total > limit) throw UpdateRejected()
        digest.update(buffer, 0, count)
        output.write(buffer, 0, count)
    }
}

private fun removeStage(directory: File): Boolean = runCatching {
    Files.deleteIfExists(File(directory, "update.apk").toPath())
    Files.deleteIfExists(directory.toPath())
    true
}.getOrDefault(false)
