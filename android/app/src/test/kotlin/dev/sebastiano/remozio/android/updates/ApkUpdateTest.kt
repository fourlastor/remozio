package dev.sebastiano.remozio.android.updates

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking

class ApkUpdateTest {
    private fun identity(version: Long = 2, name: String = "dev.sebastiano.remozio.android",
        signers: Set<String> = setOf("new"), history: List<String> = listOf("old", "new"),
        min: Int = 37, target: Int = 37, debug: Boolean = false, test: Boolean = false, split: Boolean = false) =
        ApkIdentity(name, version, "test", signers, history, min, target, debug, test, split)
    private val installed = identity(1, signers = setOf("old"), history = listOf("old"))

    @Test fun acceptsSameSignerAndForwardAuthenticatedRotation() {
        checkUpdate(installed, identity(signers = setOf("old"), history = listOf("old")), 37)
        checkUpdate(installed, identity(), 37)
        val multi = identity(1, signers = setOf("a", "b"), history = emptyList())
        checkUpdate(multi, identity(signers = setOf("b", "a"), history = emptyList()), 37)
    }

    @Test fun rejectsUnrelatedKeysPartialSignerSetsAndReverseRotation() {
        val candidates = listOf(identity(signers = emptySet()), identity(history = listOf("new")),
            identity(history = listOf("new", "old")), identity(signers = setOf("old", "other")))
        candidates.forEach { assertFailsWith<UpdateRejected> { checkUpdate(installed, it, 37) } }
        val rotated = identity(1)
        assertFailsWith<UpdateRejected> {
            checkUpdate(rotated, identity(signers = setOf("old"), history = listOf("old")), 37)
        }
        assertFailsWith<UpdateRejected> {
            checkUpdate(identity(1, signers = setOf("a", "b")), identity(signers = setOf("a")), 37)
        }
    }

    @Test fun rejectsWrongPackageVersionSdkAndProductionToDebugChanges() {
        val candidates = listOf(identity(name = "dev.sebastiano.remozio.android.debug"), identity(version = 1),
            identity(version = 0), identity(min = 36), identity(min = 38), identity(target = 36),
            identity(debug = true), identity(test = true), identity(split = true))
        candidates.forEach { assertFailsWith<UpdateRejected> { checkUpdate(installed, it, 37) } }
        checkUpdate(identity(1, debug = true, test = true), identity(debug = true, test = true), 37)
    }

    private class Source(bytes: ByteArray) : ByteArrayInputStream(bytes) {
        var wasClosed = false
        override fun close() { wasClosed = true; super.close() }
    }
    private class Inspector(val current: ApkIdentity, val candidate: ApkIdentity) : ApkInspector {
        var file: File? = null
        var inspection: (File) -> Unit = {}
        override fun installed() = current
        override fun verify(file: File): ApkIdentity {
            this.file = file
            inspection(file)
            return candidate
        }
    }
    private fun withCache(block: (File) -> Unit) {
        val cache = Files.createTempDirectory("remozio-update-test-").toFile()
        try { block(cache) } finally { cache.deleteRecursively() }
    }

    @Test fun stagesExactBoundVerifiesCopiesAndReleasesWithoutTouchingOtherFiles() = withCache { cache -> runBlocking {
        val unrelated = File(cache, "keep").apply { writeText("keep") }
        val inspector = Inspector(installed, identity())
        val verifier = StagedApkVerifier(cache, inspector, 37, 4)
        val source = Source(byteArrayOf(1, 2, 3, 4))
        val result = verifier.stage(source)
        assertTrue(source.wasClosed)
        assertEquals(4L, result.size)
        assertEquals(2L, result.identity.versionCode)
        val output = ByteArrayOutputStream()
        result.copyToUncommittedSession(output)
        assertContentEquals(byteArrayOf(1, 2, 3, 4), output.toByteArray())
        result.close()
        result.close()
        assertEquals(listOf(unrelated), cache.listFiles()!!.toList())
        assertFailsWith<UpdateRejected> { result.copyToUncommittedSession(output) }
        verifier.stage(Source(byteArrayOf(5))).close()
    } }

    @Test fun rejectsEmptyAndOversizedInputBeforePlatformParsingAndCleansUp() = withCache { cache -> runBlocking {
        val inspector = Inspector(installed, identity())
        val verifier = StagedApkVerifier(cache, inspector, 37, 4)
        for (bytes in listOf(byteArrayOf(), ByteArray(5))) {
            val source = Source(bytes)
            assertFailsWith<UpdateRejected> { verifier.stage(source) }
            assertTrue(source.wasClosed)
            assertEquals(null, inspector.file)
            assertTrue(cache.listFiles()!!.isEmpty())
        }
        verifier.stage(Source(byteArrayOf(1))).close()
    } }

    @Test fun platformAndPolicyFailuresNeverYieldAHandle() = withCache { cache -> runBlocking {
        val inspector = Inspector(installed, identity())
        val verifier = StagedApkVerifier(cache, inspector, 37, 8)
        inspector.inspection = { throw IOException("untrusted parser detail") }
        val error = assertFailsWith<UpdateRejected> { verifier.stage(Source(byteArrayOf(1))) }
        assertEquals("The update could not be verified", error.message)
        assertEquals(null, error.cause)
        assertTrue(cache.listFiles()!!.isEmpty())
        val wrong = StagedApkVerifier(cache, Inspector(installed, identity(name = "other")), 37, 8)
        assertFailsWith<UpdateRejected> { wrong.stage(Source(byteArrayOf(1))) }
        assertTrue(cache.listFiles()!!.isEmpty())
    } }

    @Test fun rejectsBytesChangedDuringInspectionOrBeforeHandoff() = withCache { cache -> runBlocking {
        val inspector = Inspector(installed, identity())
        val verifier = StagedApkVerifier(cache, inspector, 37, 8)
        inspector.inspection = { it.setWritable(true); it.writeBytes(byteArrayOf(2)) }
        assertFailsWith<UpdateRejected> { verifier.stage(Source(byteArrayOf(1))) }
        assertTrue(cache.listFiles()!!.isEmpty())
        inspector.inspection = {}
        val result = verifier.stage(Source(byteArrayOf(1)))
        inspector.file!!.apply { setWritable(true); writeBytes(byteArrayOf(3)) }
        val output = ByteArrayOutputStream()
        assertFailsWith<UpdateRejected> { result.copyToUncommittedSession(output) }
        // The caller must discard an uncommitted session, even when it received bytes before rejection.
        assertContentEquals(byteArrayOf(3), output.toByteArray())
        result.close()
    } }

    @Test fun boundsOutstandingFilesAndClosesRejectedSources() = withCache { cache -> runBlocking {
        val verifier = StagedApkVerifier(cache, Inspector(installed, identity()), 37, 8)
        val first = verifier.stage(Source(byteArrayOf(1)))
        val second = Source(byteArrayOf(2))
        assertFailsWith<UpdateRejected> { verifier.stage(second) }
        assertTrue(second.wasClosed)
        assertEquals(1, cache.listFiles()!!.size)
        first.close()
        verifier.stage(Source(byteArrayOf(3))).close()
        assertTrue(cache.listFiles()!!.isEmpty())
    } }

    @Test fun failedInputReleasesCapacityAndClosesSource() = withCache { cache -> runBlocking {
        val verifier = StagedApkVerifier(cache, Inspector(installed, identity()), 37, 8)
        var closed = false
        val source = object : InputStream() {
            override fun read(): Int = throw IOException("source failed")
            override fun close() { closed = true }
        }
        assertFailsWith<UpdateRejected> { verifier.stage(source) }
        assertTrue(closed)
        assertTrue(cache.listFiles()!!.isEmpty())
        verifier.stage(Source(byteArrayOf(1))).close()
    } }

    @Test fun cancellationBeforeDispatchStillClosesInput() = withCache { cache -> runBlocking {
        val verifier = StagedApkVerifier(cache, Inspector(installed, identity()), 37, 8)
        val source = Source(byteArrayOf(1))
        assertFailsWith<CancellationException> {
            coroutineScope { cancel(); verifier.stage(source) }
        }
        assertTrue(source.wasClosed)
        assertTrue(cache.listFiles()!!.isEmpty())
        verifier.stage(Source(byteArrayOf(1))).close()
    } }
    @Test fun failedCleanupRetainsCapacityUntilTheHandleCanBeClosed() = withCache { cache -> runBlocking {
        val inspector = Inspector(installed, identity())
        val verifier = StagedApkVerifier(cache, inspector, 37, 8)
        val first = verifier.stage(Source(byteArrayOf(1)))
        val unexpected = File(inspector.file!!.parentFile, "unexpected").apply { writeText("retain") }
        assertFailsWith<UpdateRejected> { first.close() }
        assertTrue(unexpected.exists())
        assertFailsWith<UpdateRejected> { verifier.stage(Source(byteArrayOf(2))) }
        unexpected.delete()
        first.close()
        verifier.stage(Source(byteArrayOf(3))).close()
        assertTrue(cache.listFiles()!!.isEmpty())
    } }

}
