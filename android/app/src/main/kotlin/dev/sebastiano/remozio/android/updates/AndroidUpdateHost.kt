package dev.sebastiano.remozio.android.updates

import android.content.Context
import android.os.Build
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.launch

internal object UpdateSignals {
    val changes = MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)
}

internal fun androidUpdateHost(context: Context, scope: CoroutineScope): UpdateHost {
    val app = context.applicationContext
    val packages = app.packageManager
    val staging = File(app.cacheDir, "updates-v1")
    val host = UpdateHost(scope, { openUpdateRecords(app) },
        { Files.createDirectories(staging.toPath()); StagedApkVerifier(staging, AndroidApkInspector(app), Build.VERSION.SDK_INT) },
        { record -> AndroidUpdateInstallBackend(app) { id ->
            openUpdateRecords(app).use { updateStatusReceiver(app, it, record.nonce, id) }
        } },
        { packages.getPackageInfo(app.packageName, 0).let { it.versionName ?: it.longVersionCode.toString() } },
        { packages.canRequestPackageInstalls() },
        {
            val installer = packages.packageInstaller
            val sessions = installer.mySessions.filter { it.appPackageName == app.packageName }
            if (sessions.any { it.isCommitted }) false else {
                sessions.forEach { installer.abandonSession(it.sessionId) }
                installer.mySessions.none { it.appPackageName == app.packageName }
            }
        },
        { cleanUpdateStaging(staging) },
        { UpdateConfirmationNotifications(app).existing(it) != null },
        Build.VERSION.SDK_INT, GitHubUpdates(), AndroidUpdatePreferences(app),
    )
    scope.launch { UpdateSignals.changes.collect { host.refresh().join() } }
    return host
}

/** Deletes only this updater's known staging names, without following a directory or file link. */
internal fun cleanUpdateStaging(root: File): Boolean = runCatching {
    val path = root.toPath()
    if (!Files.exists(path, NOFOLLOW_LINKS)) return@runCatching true
    check(Files.isDirectory(path, NOFOLLOW_LINKS))
    Files.newDirectoryStream(path).use { entries ->
        for (directory in entries) {
            check(directory.fileName.toString().startsWith("remozio-update-") && Files.isDirectory(directory, NOFOLLOW_LINKS))
            Files.newDirectoryStream(directory).use { children ->
                for (file in children) {
                    check(file.fileName.toString() == "update.apk" && Files.isRegularFile(file, NOFOLLOW_LINKS))
                    Files.delete(file)
                }
            }
            Files.delete(directory)
        }
    }
    true
}.getOrDefault(false)
