package dev.sebastiano.remozio.android.updates

import java.io.ByteArrayInputStream
import java.net.URI
import kotlin.test.*
import kotlinx.coroutines.*
import org.junit.Test

class GitHubUpdatesTest {
    private fun release(tag: String = "v0.2.0", size: Long = 3, prerelease: Boolean = false, draft: Boolean = false,
        assets: String = """[{"name":"$ANDROID_RELEASE_ASSET","state":"uploaded","size":$size}]""") =
        """{"tag_name":"$tag","draft":$draft,"prerelease":$prerelease,"assets":$assets}"""

    private class Body(bytes: ByteArray) : ByteArrayInputStream(bytes) {
        var closed = false
        override fun close() { closed = true; super.close() }
    }
    private fun source(text: String) = GitHubUpdates(ReleaseHttp { _, _ -> ReleaseResponse(200, null, text.byteInputStream()) })

    @Test fun stableReleaseOffersOnlyANewerStandaloneAsset() = runBlocking {
        assertEquals(ReleaseCandidate("v0.2.0", 3), source(release()).check("0.1.0", false))
        assertNull(source(release()).check("0.2.0", false))
        assertNull(source(release()).check("0.3.0", false))
        assertNull(source(release(draft = true)).check("0.1.0", false))
        assertNull(source(release(prerelease = true)).check("0.1.0", false))
        assertNull(source(release(tag = "v0.3.0-beta.1")).check("0.1.0", false))
        assertNull(source(release(assets = "[]")).check("0.1.0", false))
    }

    @Test fun prereleaseSelectionUsesVersionPrecedenceNotResponseOrder() = runBlocking {
        val releases = "[${release("v1.0.0-beta.2", prerelease = true)},${release("v0.9.0")},${release("v1.0.0-beta.12", prerelease = true)}]"
        assertEquals("v1.0.0-beta.12", source(releases).check("1.0.0-beta.1", true)!!.tag)
        assertNull(source(releases).check("1.0.0", true))
        val order = listOf("1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0")
        order.zipWithNext().forEach { (a, b) -> assertTrue(ReleaseVersion.parse(a)!! < ReleaseVersion.parse(b)!!) }
        assertEquals(ReleaseVersion.parse("1.0.0+a"), ReleaseVersion.parse("1.0.0+b"))
    }

    @Test fun invalidVersionsAndAmbiguousAssetsAreNotOffered() = runBlocking {
        listOf("1.0", "01.0.0", "1.0.0-01", "1.0.0/escape", "1.0.0%2f", "2147483648.0.0", "v", "1.0.0+").forEach {
            assertNull(ReleaseVersion.parse(it), it)
            assertNull(source(release(tag = it)).check("0.1.0", false))
        }
        val duplicate = """[{"name":"$ANDROID_RELEASE_ASSET","state":"uploaded","size":3},{"name":"$ANDROID_RELEASE_ASSET","state":"uploaded","size":4}]"""
        assertNull(source(release(assets = duplicate)).check("0.1.0", false))
        assertNull(source(release(size = MAX_UPDATE_BYTES + 1)).check("0.1.0", false))
        assertNull(source(release(size = 0)).check("0.1.0", false))
    }

    @Test fun boundsMetadataSizeAndDepthAndRejectsInvalidUtf8() = runBlocking {
        val payloads = listOf(ByteArray(2 * 1024 * 1024 + 1) { 32 }, ("[".repeat(33) + "]".repeat(33)).toByteArray(), byteArrayOf(0xc3.toByte(), 0x28))
        for (bytes in payloads) {
            val body = Body(bytes)
            val source = GitHubUpdates(ReleaseHttp { _, _ -> ReleaseResponse(200, null, body) })
            assertFails { source.check("0.1.0", true) }
            assertTrue(body.closed)
        }
    }

    @Test fun closesMissingAndFailedResponses() = runBlocking {
        for (status in listOf(404, 403, 429, 500)) {
            val body = Body(byteArrayOf())
            val source = GitHubUpdates(ReleaseHttp { _, _ -> ReleaseResponse(status, null, body) })
            if (status == 404) assertNull(source.check("0.1.0", false)) else assertFails { source.check("0.1.0", false) }
            assertTrue(body.closed)
        }
        val body = Body(byteArrayOf())
        assertFails { GitHubUpdates(ReleaseHttp { _, _ -> ReleaseResponse(500, null, body) }).open(ReleaseCandidate("v0.2.0", 3)) }
        assertTrue(body.closed)
    }

    @Test fun downloadStartsAtFixedRepositoryAndClosesRedirectBodies() = runBlocking {
        val first = Body(byteArrayOf())
        val last = Body(byteArrayOf(1, 2, 3))
        val urls = mutableListOf<URI>()
        val source = GitHubUpdates(ReleaseHttp { url, metadata ->
            assertFalse(metadata)
            urls += url
            if (urls.size == 1) ReleaseResponse(302, "https://release-assets.githubusercontent.com/example?signed=opaque", first)
            else ReleaseResponse(200, null, last)
        })
        source.open(ReleaseCandidate("v0.2.0", 3)).use { assertContentEquals(byteArrayOf(1, 2, 3), it.readBytes()) }
        assertEquals("https://github.com/rock3r/remozio/releases/download/v0.2.0/remozio-android.apk", urls.first().toString())
        assertTrue(first.closed && last.closed)
    }

    @Test fun rejectsRedirectsOutsideHttpsAllowlistBeforeOpeningThem() = runBlocking {
        for (url in listOf("http://github.com/x", "https://example.com/x", "https://github.com:444/x", "https://user:secret@github.com/x", "https://github.com/x#fragment")) {
            val body = Body(byteArrayOf())
            var calls = 0
            val source = GitHubUpdates(ReleaseHttp { _, _ -> calls++; ReleaseResponse(302, url, body) })
            assertFails { source.open(ReleaseCandidate("v0.2.0", 3)) }
            assertEquals(1, calls)
            assertTrue(body.closed)
        }
    }

    @Test fun redirectLoopStopsAndClosesEveryBody() = runBlocking {
        val bodies = mutableListOf<Body>()
        val source = GitHubUpdates(ReleaseHttp { _, _ ->
            val body = Body(byteArrayOf()).also { bodies += it }
            ReleaseResponse(302, "https://github.com/loop", body)
        })
        assertFails { source.open(ReleaseCandidate("v0.2.0", 3)) }
        assertEquals(6, bodies.size)
        assertTrue(bodies.all { it.closed })
    }

    @Test fun cancelledReadClosesTheDownloadStream() = runBlocking {
        val body = Body(byteArrayOf(1, 2, 3))
        lateinit var job: Job
        val source = GitHubUpdates(ReleaseHttp { _, _ -> job.cancel(); ReleaseResponse(200, null, body) })
        job = launch(start = CoroutineStart.LAZY) { source.open(ReleaseCandidate("v0.2.0", 3)).use { it.read() } }
        job.start(); job.join()
        assertTrue(job.isCancelled)
        assertTrue(body.closed)
    }

    @Test fun preferencesHandleIntervalsDisabledChecksAndClockRollback() {
        val settings = UpdatePreferences(lastAttemptMillis = 1000)
        assertFalse(settings.due(1001))
        assertTrue(settings.due(1000 + 24 * 3_600_000L))
        assertTrue(settings.due(999))
        assertFalse(settings.copy(automatic = false).due(Long.MAX_VALUE))
        assertFails { UpdatePreferences(intervalHours = 0) }
        assertFails { UpdatePreferences(intervalHours = 169) }
    }
}
