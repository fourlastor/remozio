package dev.sebastiano.remozio.android.updates

import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

internal class InstallPermissionRequired : Exception("Allow Remozio to request app installation")
internal data class InstallAttempt(val sessionId: Int, val packageName: String, val versionCode: Long)
internal enum class InstallSubmissionState { REQUESTED, UNKNOWN }
internal data class InstallSubmission(val attempt: InstallAttempt, val state: InstallSubmissionState)

internal interface UpdateInstallSession : AutoCloseable {
    val id: Int
    fun openWrite(size: Long): OutputStream
    fun fsync(output: OutputStream)
    fun commit()
    fun abandon()
}

internal interface UpdateInstallBackend {
    fun canRequestInstallation(): Boolean
    fun installed(): ApkIdentity
    fun create(identity: ApkIdentity, size: Long): UpdateInstallSession
}

/** The host must atomically persist [recordCommitIntent] before it returns, or throw to prevent commit. */
internal class UpdateInstaller(
    private val backend: UpdateInstallBackend,
    private val deviceSdk: Int,
    private val recordCommitIntent: (InstallAttempt) -> Unit,
) {
    private val occupied = AtomicBoolean()
    private var pendingCleanup: VerifiedApk? = null
    private val mutableCleanupRequired = MutableStateFlow(false)
    val cleanupRequired = mutableCleanupRequired.asStateFlow()

    /** Blocking cleanup only. It never repeats a commit or changes its reported outcome. */
    @Synchronized fun retryCleanup(): Boolean {
        val apk = pendingCleanup ?: return true
        if (runCatching { apk.close() }.isFailure) return false
        pendingCleanup = null
        mutableCleanupRequired.value = false
        return true
    }

    @Synchronized private fun retainForCleanup(apk: VerifiedApk) {
        check(pendingCleanup == null)
        pendingCleanup = apk
        mutableCleanupRequired.value = true
    }

    /** Permission, busy, and pending-cleanup rejection retain [apk]. Once preparation starts, this method owns it. */
    suspend fun submit(apk: VerifiedApk): InstallSubmission {
        var ownsApk = false
        var acquired = false
        try {
            return withContext(Dispatchers.IO) {
                if (!occupied.compareAndSet(false, true)) throw UpdateRejected()
                acquired = true
                if (cleanupRequired.value) throw UpdateRejected()
                if (!backend.canRequestInstallation()) throw InstallPermissionRequired()
                ownsApk = true
                checkUpdate(backend.installed(), apk.identity, deviceSdk)
                var session: UpdateInstallSession? = null
                var commitStarted = false
                var attempt: InstallAttempt? = null
                try {
                    coroutineContext.ensureActive()
                    session = backend.create(apk.identity, apk.size)
                    session.openWrite(apk.size).use { output ->
                        val cancellable = object : OutputStream() {
                            override fun write(value: Int) {
                                coroutineContext.ensureActive()
                                output.write(value)
                            }
                            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                                coroutineContext.ensureActive()
                                output.write(bytes, offset, length)
                            }
                        }
                        apk.copyToUncommittedSession(cancellable)
                        coroutineContext.ensureActive()
                        session.fsync(output)
                    }
                    checkUpdate(backend.installed(), apk.identity, deviceSdk)
                    coroutineContext.ensureActive()
                    attempt = InstallAttempt(session.id, apk.identity.packageName, apk.identity.versionCode)
                    recordCommitIntent(attempt)
                    coroutineContext.ensureActive()
                    commitStarted = true
                    session.commit()
                    InstallSubmission(attempt, InstallSubmissionState.REQUESTED)
                } catch (error: Exception) {
                    if (commitStarted) {
                        InstallSubmission(requireNotNull(attempt), InstallSubmissionState.UNKNOWN)
                    } else {
                        if (error is CancellationException) throw error
                        throw UpdateRejected()
                    }
                } finally {
                    if (!commitStarted) session?.let { runCatching { it.abandon() } }
                    session?.let { runCatching { it.close() } }
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (permission: InstallPermissionRequired) {
            throw permission
        } catch (_: Exception) {
            throw UpdateRejected()
        } finally {
            try {
                if (ownsApk) withContext(Dispatchers.IO + NonCancellable) {
                    if (runCatching { apk.close() }.isFailure) retainForCleanup(apk)
                }
            } finally {
                if (acquired) occupied.set(false)
            }
        }
    }
}
