package dev.remozio.android.push

import android.Manifest
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageManager
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import dev.remozio.android.requests.CommandNotificationIntents
import dev.remozio.android.requests.CommandNotificationTarget
import dev.remozio.android.R
import dev.remozio.phone.push.PhoneWakeScheduler
import dev.remozio.phone.push.PushWakeRouter
import dev.remozio.phone.push.WakeEnrollment
import dev.remozio.phone.push.WakeNotificationResult
import dev.remozio.phone.push.WakeReceipt
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.CborValue

/** Generic hints only. Request details and usable actions require a separately authenticated fetch. */
class AndroidWakeNotifications(context: Context, private val timeoutMillis: Long) {
    private val context = context.applicationContext
    private val manager = requireNotNull(this.context.getSystemService(NotificationManager::class.java))

    init { require(timeoutMillis in 1..86_400_000) }

    fun post(enrollment: WakeEnrollment, alert: Boolean): WakeNotificationResult = post(tag(enrollment), alert)
    internal fun postForRecord(recordID: CborValue.Bytes, alert: Boolean): WakeNotificationResult = post(recordTag(recordID), alert)
    internal fun postRequest(target: CommandNotificationTarget, timeout: Long): WakeNotificationResult {
        val generic = recordTag(target.recordID)
        val hinted = try { manager.activeNotifications.any { it.id == NOTIFICATION_ID && it.tag == generic } }
            catch (_: RuntimeException) { false }
        val result = post(requestTag(target), !hinted, target, timeout)
        if (result == WakeNotificationResult.POSTED) try { manager.cancel(generic, NOTIFICATION_ID) } catch (_: RuntimeException) { }
        return result
    }
    internal fun cancelRequest(target: CommandNotificationTarget) { manager.cancel(requestTag(target), NOTIFICATION_ID) }
    private fun requestTag(target: CommandNotificationTarget) = recordTag(target.recordID) + ".request." + target.encode()
    private fun post(tag: String, alert: Boolean, target: CommandNotificationTarget? = null,
                     timeout: Long = timeoutMillis): WakeNotificationResult {
        if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return WakeNotificationResult.PERMISSION_DENIED
        }
        if (!manager.areNotificationsEnabled()) return WakeNotificationResult.APP_DISABLED
        return try {
            RequestNotificationChannel.ensure(context, manager)
            if (manager.getNotificationChannel(RequestNotificationChannel.ID)?.importance == NotificationManager.IMPORTANCE_NONE) {
                return WakeNotificationResult.CHANNEL_DISABLED
            }
            // A push supplies only the generic route. Specific targets come from authenticated sessions.
            val intent = if (target == null) CommandNotificationIntents.inbox(context) else CommandNotificationIntents.request(context, target)
            val open = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val notification = NotificationCompat.Builder(context, RequestNotificationChannel.ID)
                .setSmallIcon(R.drawable.ic_launcher_monochrome)
                .setContentTitle(context.getString(R.string.app_name))
                .setContentText(context.getString(R.string.request_notification_generic))
                .setContentIntent(open)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                .setAutoCancel(true)
                .setOnlyAlertOnce(target != null || !alert)
                .setSilent(!alert)
                .setTimeoutAfter(timeout)
                .build()
            manager.notify(tag, NOTIFICATION_ID, notification)
            WakeNotificationResult.POSTED
        } catch (_: SecurityException) {
            WakeNotificationResult.PERMISSION_DENIED
        } catch (_: RuntimeException) {
            WakeNotificationResult.FAILED
        }
    }

    fun cancel(enrollment: WakeEnrollment) { manager.cancel(tag(enrollment), NOTIFICATION_ID) }
    internal fun cancelRecord(recordID: CborValue.Bytes) {
        val prefix = recordTag(recordID)
        manager.activeNotifications.filter { it.id == NOTIFICATION_ID && (it.tag == prefix || it.tag?.startsWith(prefix + ".request.") == true) }
            .forEach { manager.cancel(it.tag, it.id) }
    }
    private fun recordTag(recordID: CborValue.Bytes): String {
        val bytes = recordID.copyBytes(); require(bytes.size == 16)
        return "remozio.wake.record." + bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    }
    fun cancelAll(): Boolean = try {
        manager.activeNotifications.filter { it.id == NOTIFICATION_ID && it.tag?.startsWith("remozio.wake.") == true }
            .forEach { manager.cancel(it.tag, it.id) }
        true
    } catch (_: RuntimeException) { false }

    private fun tag(enrollment: WakeEnrollment): String = "remozio.wake." +
        enrollment.notificationTag.copyBytes().joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        const val NOTIFICATION_ID = 1
    }
}

/** Own alongside the same process-local router and scheduler, within an admitted Android work window. */
class AndroidPushWakeReceiver(
    private val router: PushWakeRouter,
    private val notifications: AndroidWakeNotifications,
    private val clockEpoch: Long,
    private val scheduler: PhoneWakeScheduler,
) {
    fun receive(data: Map<String, String>): WakeReceipt = router.receive(data,
        { ElapsedInstant(clockEpoch, SystemClock.elapsedRealtime().toULong()) }, notifications::post).also { scheduler.signal() }

    fun remove(enrollment: WakeEnrollment): Boolean {
        if (!router.remove(enrollment)) return false
        scheduler.signal()
        notifications.cancel(enrollment)
        return true
    }
}
