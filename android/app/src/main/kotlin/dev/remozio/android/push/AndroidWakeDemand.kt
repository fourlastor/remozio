package dev.remozio.android.push

import android.content.Context
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import androidx.annotation.WorkerThread
import dev.remozio.android.storage.ExclusiveFileOwner
import dev.remozio.phone.push.PendingWakeDemand
import dev.remozio.phone.push.WakeDemandStorage
import dev.remozio.phone.push.WakeDemandTicket
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.util.UUID

/** Owns private scheduling state. It grants no request or decision authority. */
internal class AndroidWakeDemand private constructor(
    private val storage: WakeDemandFile,
    private val demand: PendingWakeDemand,
) : WakeDemandStore {
    private var closed = false

    /** The caller holds the current provider configuration lock. */
    @Synchronized override fun selectGeneration(generation: UUID) {
        check(!closed); demand.selectGeneration(generation)
    }
    @Synchronized override fun mark(generation: UUID, tag: ByteArray): WakeDemandTicket {
        check(!closed); return demand.mark(generation, tag)
    }
    @Synchronized override fun pending(generation: UUID): List<WakeDemandTicket> {
        check(!closed); return demand.pending(generation)
    }
    @Synchronized override fun complete(ticket: WakeDemandTicket): Boolean {
        check(!closed); return demand.complete(ticket)
    }
    @Synchronized override fun close() {
        if (!closed) { closed = true; storage.close() }
    }

    companion object {
        /** Call off the main thread. Reopening reads the durable journal after an uncertain commit. */
        @WorkerThread fun open(context: Context, maximumEntries: Int = 1024): AndroidWakeDemand {
            require(maximumEntries in 1..1024)
            val app = context.applicationContext
            check(!app.isDeviceProtectedStorage)
            val directory = File(app.noBackupFilesDir, "wake-demand")
            if (!directory.isDirectory) {
                check(directory.mkdirs()); syncWakeDirectory(app.noBackupFilesDir)
            }
            val storage = WakeDemandFile(File(directory, "state"))
            return try { AndroidWakeDemand(storage, PendingWakeDemand(storage, maximumEntries)) }
            catch (failure: Throwable) { storage.close(); throw failure }
        }
    }
}

private class WakeDemandFile(private val file: File) : WakeDemandStorage, AutoCloseable {
    private val owner = ExclusiveFileOwner.acquire(File(file.path + ".lock"))
    private val atomic = AtomicFile(file)
    private var closed = false

    @Synchronized override fun read(maximumBytes: Int): ByteArray? {
        check(!closed); require(maximumBytes in 1..262_144)
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
        check(!closed); require(bytes.size in 1..262_144)
        val output = atomic.startWrite()
        try { output.write(bytes); output.fd.sync(); atomic.finishWrite(output) }
        catch (failure: Exception) { atomic.failWrite(output); throw failure }
        syncWakeDirectory(requireNotNull(file.parentFile))
        check(read(bytes.size)?.contentEquals(bytes) == true)
    }
    @Synchronized override fun close() {
        if (!closed) { closed = true; owner.close() }
    }
}

private fun syncWakeDirectory(directory: File) {
    val descriptor = Os.open(directory.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
    try { check(OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode)); Os.fsync(descriptor) }
    finally { Os.close(descriptor) }
}
