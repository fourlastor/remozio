package dev.sebastiano.remozio.android.push

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.Settings
import androidx.core.app.NotificationCompat
import dev.sebastiano.remozio.android.MainActivity
import dev.sebastiano.remozio.android.R

internal object RequestNotificationChannel {
    const val ID = "pending_requests_v1"
    fun ensure(context: Context, manager: NotificationManager) {
        manager.createNotificationChannel(NotificationChannel(ID,
            context.getString(R.string.request_notification_channel), NotificationManager.IMPORTANCE_HIGH).apply {
            description = context.getString(R.string.request_notification_channel_description)
        })
    }
}

/** Only local notification diagnostics. No enrollment, provider or request authority is accessed. */
internal class AndroidNotificationSetup(context: Context) {
    private val app = context.applicationContext
    private val manager get() = requireNotNull(app.getSystemService(NotificationManager::class.java))

    fun read(): NotificationAccess = try {
        notificationAccess(app.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED,
            manager.areNotificationsEnabled(), manager.getNotificationChannel(RequestNotificationChannel.ID)?.importance)
    } catch (_: RuntimeException) { NotificationAccess.UNAVAILABLE }

    fun prepare(): Boolean = try { RequestNotificationChannel.ensure(app, manager); true }
        catch (_: RuntimeException) { false }

    fun settingsIntent(channel: Boolean): Intent = Intent(
        if (channel) Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS else Settings.ACTION_APP_NOTIFICATION_SETTINGS,
    ).putExtra(Settings.EXTRA_APP_PACKAGE, app.packageName).apply {
        if (channel) putExtra(Settings.EXTRA_CHANNEL_ID, RequestNotificationChannel.ID)
    }

    fun postLocalTest(): LocalNotificationResult {
        if (!read().canTest) return LocalNotificationResult.BLOCKED
        return try {
            if (app.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                return LocalNotificationResult.BLOCKED
            }
            val open = PendingIntent.getActivity(app, 1, Intent(app, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val notification = NotificationCompat.Builder(app, RequestNotificationChannel.ID)
                .setSmallIcon(R.drawable.ic_launcher_monochrome)
                .setContentTitle(app.getString(R.string.notification_test_title))
                .setContentText(app.getString(R.string.notification_test_body))
                .setContentIntent(open).setAutoCancel(true).setOnlyAlertOnce(true)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                .setCategory(NotificationCompat.CATEGORY_STATUS).setTimeoutAfter(60_000).build()
            manager.notify(TEST_TAG, TEST_ID, notification)
            LocalNotificationResult.SUBMITTED
        } catch (_: SecurityException) { LocalNotificationResult.BLOCKED }
          catch (_: RuntimeException) { LocalNotificationResult.FAILED }
    }

    fun clearLocalTest(): LocalNotificationResult = try {
        manager.cancel(TEST_TAG, TEST_ID)
        LocalNotificationResult.CLEARED
    } catch (_: RuntimeException) { LocalNotificationResult.FAILED }

    private companion object {
        const val TEST_TAG = "remozio.local-notification-test"
        const val TEST_ID = 1
    }
}
