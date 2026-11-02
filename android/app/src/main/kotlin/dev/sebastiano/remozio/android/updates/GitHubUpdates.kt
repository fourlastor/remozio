package dev.sebastiano.remozio.android.updates

import java.io.FilterInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.URI
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.json.*

internal const val MAX_UPDATE_BYTES = 256L * 1024 * 1024
internal const val ANDROID_RELEASE_ASSET = "remozio-android.apk"

internal data class ReleaseVersion(val numbers: List<Int>, val prerelease: List<String>) : Comparable<ReleaseVersion> {
    override fun compareTo(other: ReleaseVersion): Int {
        numbers.zip(other.numbers).forEach { (a, b) -> if (a != b) return a.compareTo(b) }
        if (prerelease.isEmpty() != other.prerelease.isEmpty()) return if (prerelease.isEmpty()) 1 else -1
        prerelease.zip(other.prerelease).forEach { (a, b) ->
            if (a != b) {
                val an = a.all(Char::isDigit); val bn = b.all(Char::isDigit)
                return when {
                    an && bn -> if (a.length != b.length) a.length.compareTo(b.length) else a.compareTo(b)
                    an != bn -> if (an) -1 else 1
                    else -> a.compareTo(b)
                }
            }
        }
        return prerelease.size.compareTo(other.prerelease.size)
    }
    companion object {
        fun parse(value: String): ReleaseVersion? {
            if (value.length !in 1..128) return null
            val match = Regex("v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?")
                .matchEntire(value) ?: return null
            val numbers = (1..3).map { match.groupValues[it].toIntOrNull() ?: return null }
            val pre = match.groupValues[4].takeIf { it.isNotEmpty() }?.split('.') ?: emptyList()
            if (pre.any { it.length > 1 && it.all(Char::isDigit) && it.startsWith('0') }) return null
            return ReleaseVersion(numbers, pre)
        }
    }
}

internal data class ReleaseCandidate(val tag: String, val size: Long) {
    init { require(ReleaseVersion.parse(tag) != null && size in 1..MAX_UPDATE_BYTES) }
    val versionName get() = tag.removePrefix("v")
    val downloadUrl get() = "https://github.com/rock3r/remozio/releases/download/$tag/$ANDROID_RELEASE_ASSET"
}

internal interface UpdateReleaseSource {
    suspend fun check(installedVersion: String, prereleases: Boolean): ReleaseCandidate?
    suspend fun open(candidate: ReleaseCandidate): InputStream
}

internal class ReleaseResponse(val status: Int, val location: String?, val body: InputStream) : AutoCloseable {
    override fun close() = body.close()
}
internal fun interface ReleaseHttp { fun open(url: URI, metadata: Boolean): ReleaseResponse }

internal class GitHubUpdates(private val http: ReleaseHttp = ReleaseHttp(::openReleaseConnection)) : UpdateReleaseSource {
    override suspend fun check(installedVersion: String, prereleases: Boolean): ReleaseCandidate? {
        val installed = requireNotNull(ReleaseVersion.parse(installedVersion))
        val url = "https://api.github.com/repos/rock3r/remozio/releases" + if (prereleases) "?per_page=30" else "/latest"
        return request(url, true).use { response ->
            if (response.status == 404) return@use null
            check(response.status == 200)
            val bytes = ByteArrayOutputStream().use { output ->
                val buffer = ByteArray(8192)
                val limit = 2 * 1024 * 1024 + 1
                while (output.size() < limit) {
                    val count = response.body.read(buffer, 0, minOf(buffer.size, limit - output.size()))
                    if (count < 0) break
                    check(count > 0)
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            require(bytes.size <= 2 * 1024 * 1024)
            val text = bytes.decodeToString(throwOnInvalidSequence = true)
            checkJsonDepth(text)
            val json = Json.parseToJsonElement(text)
            val releases = if (prereleases) json.jsonArray.also { require(it.size <= 30) } else listOf(json)
            releases.mapNotNull { element ->
                val release = element.jsonObject
                if (release["draft"]?.jsonPrimitive?.booleanOrNull != false) return@mapNotNull null
                if (!prereleases && release["prerelease"]?.jsonPrimitive?.booleanOrNull != false) return@mapNotNull null
                val tag = release["tag_name"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
                val version = ReleaseVersion.parse(tag) ?: return@mapNotNull null
                if (version <= installed || !prereleases && version.prerelease.isNotEmpty()) return@mapNotNull null
                val assets = release["assets"]?.jsonArray ?: return@mapNotNull null
                require(assets.size <= 100)
                val asset = assets.map { it.jsonObject }.filter { it["name"]?.jsonPrimitive?.contentOrNull == ANDROID_RELEASE_ASSET }
                    .singleOrNull() ?: return@mapNotNull null
                if (asset["state"]?.jsonPrimitive?.contentOrNull != "uploaded") return@mapNotNull null
                val size = asset["size"]?.jsonPrimitive?.longOrNull ?: return@mapNotNull null
                if (size !in 1..MAX_UPDATE_BYTES) return@mapNotNull null
                ReleaseCandidate(tag, size)
            }.maxByOrNull { requireNotNull(ReleaseVersion.parse(it.tag)) }
        }
    }

    override suspend fun open(candidate: ReleaseCandidate): InputStream {
        val response = request(candidate.downloadUrl, false)
        if (response.status != 200) { response.close(); error("Release download unavailable") }
        return response.body
    }

    private suspend fun request(url: String, metadata: Boolean): ReleaseResponse {
        var current = URI(url)
        val context = coroutineContext
        val started = System.nanoTime()
        val deadlineNanos = (if (metadata) 60L else 30L * 60) * 1_000_000_000
        repeat(6) { hop ->
            context.ensureActive()
            check(System.nanoTime() - started < deadlineNanos)
            checkReleaseUrl(current)
            val response = http.open(current, metadata)
            if (response.status in listOf(301, 302, 303, 307, 308)) {
                response.use {
                    check(hop < 5)
                    current = current.resolve(checkNotNull(it.location))
                }
            } else {
                return ReleaseResponse(response.status, null, object : FilterInputStream(response.body) {
                    private fun checkReading() {
                        context.ensureActive()
                        check(System.nanoTime() - started < deadlineNanos) { "Download deadline exceeded" }
                    }
                    override fun read(): Int { checkReading(); return super.read().also { checkReading() } }
                    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                        checkReading(); return `in`.read(bytes, offset, length).also { checkReading() }
                    }
                })
            }
        }
        error("Too many redirects")
    }
}

internal fun checkReleaseUrl(url: URI) {
    require(url.scheme == "https" && url.userInfo == null && url.fragment == null && url.port in listOf(-1, 443))
    require(url.host in setOf("api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"))
}

private fun openReleaseConnection(url: URI, metadata: Boolean): ReleaseResponse {
    val connection = url.toURL().openConnection() as HttpsURLConnection
    try {
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 10_000
        connection.readTimeout = 15_000
        connection.useCaches = false
        connection.setRequestProperty("Accept", if (metadata) "application/vnd.github+json" else "application/octet-stream")
        connection.setRequestProperty("User-Agent", "Remozio Android updater")
        if (url.host == "api.github.com") connection.setRequestProperty("X-GitHub-Api-Version", "2026-03-10")
        val status = connection.responseCode
        val body = if (status in 200..299) connection.inputStream else connection.errorStream ?: InputStream.nullInputStream()
        return ReleaseResponse(status, connection.getHeaderField("Location"), object : FilterInputStream(body) {
            override fun close() { try { super.close() } finally { connection.disconnect() } }
        })
    } catch (error: Throwable) { connection.disconnect(); throw error }
}

private fun checkJsonDepth(text: String) {
    var depth = 0; var quoted = false; var escaped = false
    for (character in text) {
        if (quoted) {
            if (escaped) escaped = false
            else if (character == '\\') escaped = true
            else if (character == '"') quoted = false
        } else when (character) {
            '"' -> quoted = true
            '{', '[' -> { depth++; require(depth <= 32) }
            '}', ']' -> { depth--; require(depth >= 0) }
        }
    }
    require(depth == 0 && !quoted)
}
