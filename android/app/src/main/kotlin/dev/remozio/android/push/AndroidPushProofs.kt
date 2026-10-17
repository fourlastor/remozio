package dev.remozio.android.push

import android.content.Context
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import androidx.annotation.WorkerThread
import dev.remozio.android.storage.ExclusiveFileOwner
import dev.remozio.phone.push.PhonePushProofLedger
import dev.remozio.phone.push.PhonePushProofStorage
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.PhonePushRegistrationMetadata
import dev.remozio.protocol.PhonePushTokenOffer
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException

/** Durable local proof claims contain identifiers and hashes only. They grant no transmission or decision authority. */
internal class AndroidPushProofs private constructor(private val storage: PushProofFile, private val ledger: PhonePushProofLedger) : PushProofOwner {
    private var closed = false
    @Synchronized override fun retainActiveRecords(recordIDs: Set<CborValue.Bytes>) {
        check(!closed); ledger.retainActiveRecords(recordIDs)
    }
    @Synchronized override fun claim(record: StoredPhoneEnrollment, metadata: PhonePushRegistrationMetadata, offer: PhonePushTokenOffer): Boolean {
        check(!closed); return ledger.claim(record, metadata, offer)
    }
    @Synchronized override fun close() { if (!closed) { closed = true; storage.close() } }
    companion object {
        @WorkerThread fun open(context: Context, maximumEntries: Int = 1024): AndroidPushProofs {
            require(maximumEntries in 1..8192)
            val app = context.applicationContext; check(!app.isDeviceProtectedStorage)
            val directory = File(app.noBackupFilesDir, "push-proof-history")
            if (!directory.isDirectory) { check(directory.mkdirs()); syncProofDirectory(app.noBackupFilesDir) }
            val storage = PushProofFile(File(directory, "state"))
            return try { AndroidPushProofs(storage, PhonePushProofLedger(storage, maximumEntries)) }
            catch (failure: Throwable) { storage.close(); throw failure }
        }
    }
}

private class PushProofFile(private val file: File) : PhonePushProofStorage, AutoCloseable {
    private val owner = ExclusiveFileOwner.acquire(File(file.path + ".lock"))
    private val atomic = AtomicFile(file)
    private var closed = false

    @Synchronized override fun read(maximumBytes: Int): ByteArray? {
        check(!closed); require(maximumBytes in 1..1_048_576)
        val input = try { atomic.openRead() } catch (failure: FileNotFoundException) {
            if (listOf(file, File(file.path + ".bak"), File(file.path + ".new")).none { it.exists() }) return null
            throw failure
        }
        return input.use {
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = it.read(buffer)
                if (count < 0) break
                check(count <= maximumBytes - output.size())
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
    }
    @Synchronized override fun replace(bytes: ByteArray) {
        check(!closed); require(bytes.size in 1..1_048_576)
        val output = atomic.startWrite()
        try { output.write(bytes); output.fd.sync(); atomic.finishWrite(output) }
        catch (failure: Exception) { atomic.failWrite(output); throw failure }
        syncProofDirectory(requireNotNull(file.parentFile))
        check(read(bytes.size)?.contentEquals(bytes) == true)
    }
    @Synchronized override fun close() {
        if (!closed) { closed = true; owner.close() }
    }
}

private fun syncProofDirectory(directory: File) {
    val descriptor = Os.open(directory.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
    try { check(OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode)); Os.fsync(descriptor) }
    finally { Os.close(descriptor) }
}
