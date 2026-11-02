package dev.sebastiano.remozio.android.updates

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import kotlin.test.*
import kotlinx.coroutines.*
import org.junit.Test

class UpdateHostTest {
    private class Fixture {
        val root = Files.createTempDirectory("update-host").toFile()
        val cache = File(root, "cache").apply { mkdir() }
        val database = UpdateRecordTestDatabase(File(root, "record.sqlite").path)
        val records = UpdateRecordStore(database)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        var permission = true
        var backendFailure = false
        var uncertainCommit = false
        var cleanupFails = false
        var verifierFails = false
        var reconciliation = true
        var reconciliations = 0
        var commits = 0
        var sources = 0
        var offered: ReleaseCandidate? = null
        var releaseChecks = 0
        var releaseOpens = 0
        var checkFails = false
        var downloadGate: CompletableDeferred<Unit>? = null
        var savedPreferences = UpdatePreferences()
        var now = 1000L
        val installed = ApkIdentity("dev.sebastiano.remozio.android", 1, "0.1.0", setOf("signer"), listOf("signer"), 37, 37)
        val candidate = ApkIdentity("dev.sebastiano.remozio.android", 2, "0.2.0", setOf("signer"), listOf("signer"), 37, 37)
        val inspector = object : ApkInspector {
            override fun installed() = installed
            override fun verify(file: File) = candidate
        }
        val host = UpdateHost(scope, { records }, {
            if (verifierFails) error("Verifier unavailable")
            StagedApkVerifier(cache, inspector, 37)
        }, { record ->
            if (backendFailure) error("Backend unavailable")
            object : UpdateInstallBackend {
                override fun canRequestInstallation() = permission
                override fun installed() = installed
                override fun create(identity: ApkIdentity, size: Long): UpdateInstallSession {
                    records.bind(record.nonce, 7)
                    return object : UpdateInstallSession {
                        override val id = 7
                        override fun openWrite(size: Long) = ByteArrayOutputStream()
                        override fun fsync(output: java.io.OutputStream) {}
                        override fun commit() { commits++; if (uncertainCommit) error("Lost reply") }
                        override fun abandon() {}
                        override fun close() {}
                    }
                }
            }
        }, { "0.1.0" }, { permission }, { reconciliations++; reconciliation },
            { !cleanupFails && cleanUpdateStaging(cache) }, { true }, 37,
            object : UpdateReleaseSource {
                override suspend fun check(installedVersion: String, prereleases: Boolean): ReleaseCandidate? {
                    releaseChecks++
                    if (checkFails) error("Network unavailable")
                    return offered
                }
                override suspend fun open(candidate: ReleaseCandidate): java.io.InputStream {
                    releaseOpens++
                    downloadGate?.await()
                    return ByteArrayInputStream(byteArrayOf(1, 2, 3))
                }
            }, object : UpdatePreferencesStore {
                override fun load() = savedPreferences
                override fun save(value: UpdatePreferences) { savedPreferences = value }
            }, { now })
        fun stage() = host.stage { sources++; ByteArrayInputStream(byteArrayOf(1, 2, 3)) }
        suspend fun close() {
            scope.cancel()
            scope.coroutineContext.job.join()
            records.close()
            root.deleteRecursively()
        }
    }

    private suspend fun fixture(test: suspend (Fixture) -> Unit) {
        val fixture = Fixture()
        try { test(fixture) } finally { fixture.close() }
    }

    @Test fun permissionRoundTripRetainsVerifiedApkAndSubmitsOnce() = runBlocking { fixture { f ->
        f.permission = false
        f.stage().join()
        f.host.install().join()
        assertTrue(f.host.state.value.permissionRequired)
        assertEquals("0.2.0", f.host.state.value.readyVersion)
        assertNull(f.records.snapshot())
        f.host.refresh().join()
        f.permission = true
        f.host.install().join()
        assertEquals(1, f.sources)
        assertEquals(1, f.commits)
        assertNull(f.host.state.value.readyVersion)
        assertEquals(UpdatePhase.SUBMITTED, f.host.state.value.record!!.phase)
        f.host.install().join()
        assertEquals(1, f.commits)
    } }

    @Test fun startupReconcilesBeforeIntentButNeverRetriesIntent() = runBlocking { fixture { f ->
        val record = f.records.reserve(f.candidate.packageName, 2)
        f.records.bind(record.nonce, 7)
        f.host.refresh().join()
        assertEquals(UpdatePhase.ABANDONED, f.records.snapshot()!!.phase)
        assertEquals(1, f.reconciliations)
        val pending = f.records.reserve(f.candidate.packageName, 2)
        f.records.bind(pending.nonce, 7)
        f.records.recordCommitIntent(pending.nonce, InstallAttempt(7, f.candidate.packageName, 2))
        f.host.refresh().join()
        f.stage().join()
        assertEquals(0, f.sources)
        assertEquals(0, f.commits)
        assertEquals(UpdatePhase.INTENT, f.records.snapshot()!!.phase)
    } }

    @Test fun coldStartWithIntentDoesNotAbandonOrInferSuccess() = runBlocking { fixture { f ->
        val record = f.records.reserve(f.candidate.packageName, 2)
        f.records.bind(record.nonce, 7)
        f.records.recordCommitIntent(record.nonce, InstallAttempt(7, f.candidate.packageName, 2))
        f.host.refresh().join()
        assertEquals(0, f.reconciliations)
        assertEquals(0, f.commits)
        assertEquals(UpdatePhase.INTENT, f.host.state.value.record!!.phase)
    } }

    @Test fun refreshRecoversUnacknowledgedReservationWithoutLosingDownload() = runBlocking { fixture { f ->
        f.stage().join()
        f.records.reserve(f.candidate.packageName, 2)
        f.host.refresh().join()
        assertEquals(UpdatePhase.ABANDONED, f.records.snapshot()!!.phase)
        assertEquals("0.2.0", f.host.state.value.readyVersion)
        f.host.install().join()
        assertEquals(1, f.sources)
        assertEquals(1, f.commits)
    } }

    @Test fun failedNativeReconciliationPreservesPendingRecord() = runBlocking { fixture { f ->
        f.records.reserve(f.candidate.packageName, 2)
        f.reconciliation = false
        f.host.refresh().join()
        assertEquals(UpdateHostError.UNAVAILABLE, f.host.state.value.error)
        assertEquals(UpdatePhase.RESERVED, f.records.snapshot()!!.phase)
        f.reconciliation = true
        f.host.refresh().join()
        assertEquals(UpdatePhase.ABANDONED, f.records.snapshot()!!.phase)
    } }

    @Test fun backendConstructionFailureKeepsDownloadAndReconcilesReservation() = runBlocking { fixture { f ->
        f.stage().join()
        f.backendFailure = true
        f.host.install().join()
        assertEquals("0.2.0", f.host.state.value.readyVersion)
        assertEquals(UpdatePhase.ABANDONED, f.records.snapshot()!!.phase)
        f.backendFailure = false
        f.host.install().join()
        assertEquals(1, f.sources)
        assertEquals(1, f.commits)
    } }

    @Test fun lostNativeReplyStaysUnknownAcrossRefreshes() = runBlocking { fixture { f ->
        f.stage().join()
        f.uncertainCommit = true
        f.host.install().join()
        f.host.refresh().join()
        f.stage().join()
        assertEquals(UpdatePhase.UNKNOWN, f.host.state.value.record!!.phase)
        assertEquals(1, f.commits)
        assertEquals(1, f.sources)
    } }

    @Test fun callbackRefreshShowsConfirmationAndTerminalStatus() = runBlocking { fixture { f ->
        f.stage().join()
        f.host.install().join()
        val record = f.records.snapshot()!!
        f.records.callback(record.nonce, 7, UpdatePhase.AWAITING_USER)
        f.host.refresh().join()
        assertTrue(f.host.state.value.confirmationAvailable)
        f.records.callback(record.nonce, 7, UpdatePhase.SUCCESS)
        f.host.refresh().join()
        assertFalse(f.host.state.value.confirmationAvailable)
        assertEquals(UpdatePhase.SUCCESS, f.host.state.value.record!!.phase)
        assertEquals("0.1.0", f.host.state.value.installedVersion)
    } }

    @Test fun verifierInitializationCanRecoverWithoutOpeningAnEarlySource() = runBlocking { fixture { f ->
        f.verifierFails = true
        f.stage().join()
        assertEquals(0, f.sources)
        assertNotNull(f.host.state.value.error)
        f.verifierFails = false
        f.stage().join()
        assertEquals(1, f.sources)
        assertEquals("0.2.0", f.host.state.value.readyVersion)
    } }

    @Test fun failedOrphanCleanupBlocksNewSourceUntilRetrySucceeds() = runBlocking { fixture { f ->
        f.cleanupFails = true
        f.stage().join()
        assertTrue(f.host.state.value.cleanupRequired)
        assertEquals(0, f.sources)
        f.cleanupFails = false
        f.host.retryCleanup().join()
        f.stage().join()
        assertEquals("0.2.0", f.host.state.value.readyVersion)
    } }

    @Test fun discardFailureRetainsHandleAndCanBeCleanedWithoutCommit() = runBlocking { fixture { f ->
        f.stage().join()
        f.permission = false
        f.host.install().join()
        assertTrue(f.host.state.value.permissionRequired)
        val directory = f.cache.listFiles()!!.single()
        val extra = File(directory, "unexpected").apply { writeText("keep") }
        f.host.discard().join()
        assertTrue(f.host.state.value.cleanupRequired)
        assertTrue(extra.exists())
        f.host.install().join()
        assertEquals(0, f.commits)
        extra.delete()
        f.host.retryCleanup().join()
        assertNull(f.host.state.value.readyVersion)
        assertFalse(f.host.state.value.cleanupRequired)
        assertFalse(f.host.state.value.permissionRequired)
        f.stage().join()
        assertEquals("0.2.0", f.host.state.value.readyVersion)
    } }

    @Test fun automaticChecksRespectSavedIntervalAndNeverDownload() = runBlocking { fixture { f ->
        f.offered = ReleaseCandidate("v0.2.0", 3)
        f.host.onForeground().join()
        assertEquals(1, f.releaseChecks)
        assertEquals(0, f.releaseOpens)
        assertEquals(0, f.commits)
        f.host.onForeground().join()
        assertEquals(1, f.releaseChecks)
        f.now += 24 * 3_600_000L
        f.host.onForeground().join()
        assertEquals(2, f.releaseChecks)
        f.host.setPreferences(UpdatePreferences(automatic = false, overridden = true)).join()
        f.host.onForeground().join()
        assertEquals(2, f.releaseChecks)
        f.host.checkForUpdates().join()
        assertEquals(3, f.releaseChecks)
    } }

    @Test fun failedCheckDoesNotLoopOnEveryForegroundEvent() = runBlocking { fixture { f ->
        f.checkFails = true
        f.host.onForeground().join()
        assertEquals(UpdateHostError.RELEASE_CHECK, f.host.state.value.error)
        f.host.onForeground().join()
        assertEquals(1, f.releaseChecks)
        assertEquals(0, f.releaseOpens)
        assertFalse(f.host.state.value.checked)
    } }

    @Test fun releaseDownloadVerifiesBeforeOfferingInstallation() = runBlocking { fixture { f ->
        f.offered = ReleaseCandidate("v0.2.0", 3)
        f.host.checkForUpdates().join()
        assertNull(f.host.state.value.readyVersion)
        f.host.download().join()
        assertEquals("0.2.0", f.host.state.value.readyVersion)
        assertEquals(1, f.releaseOpens)
        assertEquals(0, f.commits)
        f.host.install().join()
        assertEquals(1, f.commits)
    } }

    @Test fun releaseMetadataMismatchNeverOffersTheApk() = runBlocking { fixture { f ->
        for (offered in listOf(ReleaseCandidate("v0.3.0", 3), ReleaseCandidate("v0.2.0", 4))) {
            f.offered = offered
            f.host.checkForUpdates().join()
            f.host.download().join()
            assertNull(f.host.state.value.readyVersion)
            assertEquals(UpdateHostError.VERIFICATION, f.host.state.value.error)
            assertEquals(0, f.commits)
            assertTrue(f.cache.listFiles()!!.isEmpty())
        }
    } }

    @Test fun downloadCanBeCancelledAndDuplicateClicksShareTheJob() = runBlocking { fixture { f ->
        f.offered = ReleaseCandidate("v0.2.0", 3)
        f.host.checkForUpdates().join()
        f.downloadGate = CompletableDeferred()
        val first = f.host.download()
        withTimeout(5000) { while (!f.host.state.value.downloading) yield() }
        assertSame(first, f.host.download())
        f.host.cancelDownload()
        first.join()
        assertTrue(first.isCancelled)
        assertFalse(f.host.state.value.downloading)
        assertNull(f.host.state.value.readyVersion)
        assertEquals(0, f.commits)
        f.downloadGate!!.complete(Unit)
        f.host.download().join()
        assertEquals("0.2.0", f.host.state.value.readyVersion)
    } }

    @Test fun stagingRecoveryRefusesLinksAndUnknownFiles() = runBlocking { fixture { f ->
        val outside = File(f.root, "outside").apply { mkdir() }
        val protected = File(outside, "update.apk").apply { writeText("keep") }
        val link = File(f.cache, "remozio-update-link").toPath()
        Files.createSymbolicLink(link, outside.toPath())
        assertFalse(cleanUpdateStaging(f.cache))
        assertEquals("keep", protected.readText())
        Files.delete(link)
        val dir = File(f.cache, "remozio-update-old").apply { mkdir() }
        File(dir, "update.apk").writeText("old")
        val extra = File(dir, "keep").apply { writeText("keep") }
        assertFalse(cleanUpdateStaging(f.cache))
        assertTrue(extra.exists())
        extra.delete()
        assertTrue(cleanUpdateStaging(f.cache))
    } }
}
