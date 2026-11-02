package dev.sebastiano.remozio.android.storage

import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import kotlin.test.*

class ExclusiveFileOwnerTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun rejectedSecondOpenPreservesCrossProcessLock() {
        val file = temporary.newFile("archive.lock")
        val first = ExclusiveFileOwner.acquire(file)
        try {
            assertFalse(childCanAcquire(file))
            assertFailsWith<IllegalStateException> { ExclusiveFileOwner.acquire(file) }
            assertFalse(childCanAcquire(file))
        } finally { first.close() }
        assertTrue(childCanAcquire(file))
    }

    @Test fun staleCloseCannotReleaseReplacementAndCanonicalPathsShareOwnership() {
        val file = temporary.newFile("archive.lock")
        val first = ExclusiveFileOwner.acquire(file)
        first.close()
        ExclusiveFileOwner.acquire(file).use {
            first.close()
            assertFailsWith<IllegalStateException> { ExclusiveFileOwner.acquire(File(file.parentFile, "./archive.lock")) }
        }
        ExclusiveFileOwner.acquire(file).close()
    }

    @Test fun failedFileOpenReleasesReservation() {
        val directory = temporary.newFolder("archive.lock")
        assertFailsWith<IOException> { ExclusiveFileOwner.acquire(directory) }
        assertTrue(directory.delete())
        ExclusiveFileOwner.acquire(directory).close()
    }

    @Test fun independentArchivesCanBeOwnedTogether() {
        ExclusiveFileOwner.acquire(temporary.newFile("one.lock")).use {
            ExclusiveFileOwner.acquire(temporary.newFile("two.lock")).use { }
        }
    }

    private fun childCanAcquire(file: File): Boolean {
        val source = File(temporary.root, "LockProbe.java")
        source.writeText("""
            import java.nio.channels.*;
            import java.nio.file.*;
            public class LockProbe {
                public static void main(String[] args) throws Exception {
                    try (var channel = FileChannel.open(Path.of(args[0]), StandardOpenOption.WRITE)) {
                        var lock = channel.tryLock();
                        if (lock == null) System.exit(7);
                        lock.release();
                    }
                }
            }
        """.trimIndent())
        val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
            source.path, file.path).redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(20, TimeUnit.SECONDS), "Lock probe timed out")
            val output = process.inputStream.bufferedReader().readText()
            assertTrue(process.exitValue() in setOf(0, 7), "Lock probe failed: $output")
            return process.exitValue() == 0
        } finally {
            if (process.isAlive) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
            process.inputStream.close(); process.outputStream.close(); process.errorStream.close()
        }
    }
}
