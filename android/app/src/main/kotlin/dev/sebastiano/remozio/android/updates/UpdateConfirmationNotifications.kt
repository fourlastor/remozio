package dev.sebastiano.remozio.android.updates

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.net.toUri
import androidx.core.app.NotificationCompat
import dev.sebastiano.remozio.android.MainActivity
import dev.sebastiano.remozio.android.R

internal class UpdateConfirmationNotifications(context: Context) {
    private val context = context.applicationContext
    private val manager = requireNotNull(this.context.getSystemService(NotificationManager::class.java))

    private fun intent(binding: UpdateCallbackBinding) = Intent(context, UpdateConfirmationActivity::class.java)
        .setAction(UPDATE_CONFIRM_ACTION).setData(binding.uri.toUri())

    fun retain(binding: UpdateCallbackBinding, confirmation: Intent): PendingIntent = PendingIntent.getActivity(
        context, 0, intent(binding).putExtra(Intent.EXTRA_INTENT, confirmation),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    fun existing(binding: UpdateCallbackBinding): PendingIntent? = PendingIntent.getActivity(
        context, 0, intent(binding), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_NO_CREATE,
    )

    fun post(binding: UpdateCallbackBinding) {
        if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED ||
            !manager.areNotificationsEnabled()) return
        manager.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.update_notification_channel),
            NotificationManager.IMPORTANCE_DEFAULT))
        val confirmation = existing(binding)
        val open = confirmation ?: PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        manager.notify(binding.uri, 1, NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(if (confirmation != null) R.string.update_confirmation_ready else R.string.update_needs_attention))
            .setContentIntent(open).setAutoCancel(true).setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_STATUS).build())
    }

    fun clear(binding: UpdateCallbackBinding) {
        existing(binding)?.cancel()
        manager.cancel(binding.uri, 1)
    }

    private companion object { const val CHANNEL = "app_updates_v1" }
}
