package dev.sebastiano.remozio.android.updates

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.content.pm.PackageInstaller
import androidx.core.net.toUri
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

internal fun openUpdateRecords(context: Context): UpdateRecordStore {
    val database = AndroidUpdateRecordDatabase(context)
    return try { UpdateRecordStore(database) } catch (error: Throwable) {
        database.close()
        throw error
    }
}

/** Call off the UI thread while the host owns the reserved attempt. */
internal fun updateStatusReceiver(context: Context, store: UpdateRecordStore, nonce: String, sessionId: Int): IntentSender {
    val record = store.bind(nonce, sessionId)
    check(record.packageName == context.packageName)
    val binding = UpdateCallbackBinding(sessionId, nonce)
    return PendingIntent.getBroadcast(context, 0,
        Intent(context, UpdateStatusReceiver::class.java).setAction(UPDATE_STATUS_ACTION).setData(binding.uri.toUri()),
        PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    ).intentSender
}

/** Exported=false; only the session's explicit PendingIntent grants access from outside the app UID. */
class UpdateStatusReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val decoded = runCatching {
            decodeUpdateCallback(intent.action, intent.dataString,
                intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1),
                intent.getIntExtra(PackageInstaller.EXTRA_STATUS, Int.MIN_VALUE),
                intent.getBooleanExtra(PackageInstaller.EXTRA_PRE_APPROVAL, false))
        }.getOrNull() ?: return
        val confirmation = if (decoded.phase == UpdatePhase.AWAITING_USER) runCatching {
            intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
        }.getOrNull() else null
        val packageName = runCatching { intent.getStringExtra(PackageInstaller.EXTRA_PACKAGE_NAME) }.getOrNull()
        if (packageName != null && packageName != context.packageName) return
        val pending = goAsync()
        try {
            worker.execute {
                try {
                    openUpdateRecords(context).use { store ->
                        val record = store.snapshot() ?: return@use
                        if (record.packageName != context.packageName || !decoded.binding.matches(record) ||
                            record.phase.terminal || record.phase == UpdatePhase.RESERVED || record.phase == UpdatePhase.BOUND) return@use
                        val notifications by lazy { UpdateConfirmationNotifications(context) }
                        // Keep the system capability before the durable state says confirmation is available.
                        val action = confirmation?.let { runCatching { notifications.retain(decoded.binding, it) }.getOrNull() }
                        if (!store.callback(decoded.binding.nonce, decoded.binding.sessionId, decoded.phase)) {
                            action?.cancel()
                            return@use
                        }
                        if (decoded.phase == UpdatePhase.AWAITING_USER) notifications.post(decoded.binding)
                        else notifications.clear(decoded.binding)
                    }
                } catch (_: Exception) {
                    // Preserve the durable attempt. A storage or notification error cannot establish an outcome.
                } finally {
                    UpdateSignals.changes.tryEmit(Unit)
                    pending.finish()
                }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) { pending.finish() }
    }

    private companion object {
        val worker = ThreadPoolExecutor(1, 1, 30, TimeUnit.SECONDS, ArrayBlockingQueue(8),
            { task -> Thread(task, "remozio-update-callback").apply { isDaemon = true } }).apply {
            allowCoreThreadTimeOut(true)
        }
    }
}
