package dev.sebastiano.remozio.android.storage

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.channels.FileLock

/** Holds process-local ownership before opening the OS lock channel. Close only after storage use stops. */
internal class ExclusiveFileOwner private constructor(
    private val file: RandomAccessFile,
    private val lock: FileLock,
    private val reservation: AutoCloseable,
) : AutoCloseable {
    private var closed = false

    @Synchronized override fun close() {
        if (closed) return
        closed = true
        try { lock.release() } finally { try { file.close() } finally { reservation.close() } }
    }

    companion object {
        private val held = mutableSetOf<String>()

        fun acquire(lockFile: File): ExclusiveFileOwner {
            val path = lockFile.canonicalPath
            synchronized(held) { check(held.add(path)) { "Storage already open" } }
            val reservation = AutoCloseable { synchronized(held) { held.remove(path) } }
            var opened: RandomAccessFile? = null
            try {
                val file = RandomAccessFile(lockFile, "rw")
                opened = file
                val lock = file.channel.tryLock() ?: throw IOException("Storage already open")
                return ExclusiveFileOwner(file, lock, reservation)
            } catch (failure: Throwable) {
                try { opened?.close() } finally { reservation.close() }
                throw failure
            }
        }
    }
}
