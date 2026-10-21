package dev.remozio.android.requests

import android.app.Activity
import android.app.Application
import android.app.PendingIntent
import android.app.NotificationManager
import dev.remozio.android.push.AndroidWakeNotifications
import dev.remozio.phone.push.WakeNotificationResult
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Text
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.ViewModelProvider
import dev.remozio.android.MainActivity
import dev.remozio.android.R
import dev.remozio.android.RemozioTheme
import dev.remozio.protocol.CborValue
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first

/** Run only with an empty, snapshotted emulator app. Targets are fabricated public IDs and cannot authorize anything. */
class NotificationNavigationProbeActivity : ComponentActivity() {
    private val probeScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        setContent { RemozioTheme { Text(stringResource(R.string.notification_navigation_probe)) } }
        probeScope.launch {
            val first = CompletableDeferred<MainActivity>()
            val second = CompletableDeferred<MainActivity>()
            fun target(n: Int): CommandNotificationTarget {
                fun id(value: Int, size: Int = 16) = CborValue.Bytes(ByteArray(size) { value.toByte() })
                return CommandNotificationTarget(id(n),id(20),id(100),id(5),id(7),id(8,32))
            }
            val a = target(1); val b = target(2)
            val callbacks = object : Application.ActivityLifecycleCallbacks {
                override fun onActivityResumed(activity: Activity) {
                    if (activity !is MainActivity) return
                    when (activity.intent.dataString) {
                        a.encode() -> first.complete(activity)
                        b.encode() -> second.complete(activity)
                    }
                }
                override fun onActivityCreated(activity: Activity, state: Bundle?) = Unit
                override fun onActivityStarted(activity: Activity) = Unit
                override fun onActivityPaused(activity: Activity) = Unit
                override fun onActivityStopped(activity: Activity) = Unit
                override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) = Unit
                override fun onActivityDestroyed(activity: Activity) = Unit
            }
            val notifications = AndroidWakeNotifications(this@NotificationNavigationProbeActivity,60_000)
            val manager = checkNotNull(getSystemService(NotificationManager::class.java))
            var pa: PendingIntent? = null; var pb: PendingIntent? = null; var main: MainActivity? = null
            var stage = "pending-intent-identity"
            application.registerActivityLifecycleCallbacks(callbacks)
            try {
                pa = PendingIntent.getActivity(this@NotificationNavigationProbeActivity,0,CommandNotificationIntents.request(this@NotificationNavigationProbeActivity,a),PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                pb = PendingIntent.getActivity(this@NotificationNavigationProbeActivity,0,CommandNotificationIntents.request(this@NotificationNavigationProbeActivity,b),PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                check(pa != pb)
                stage = "publish-first"
                check(notifications.postRequest(a,30_000) == WakeNotificationResult.POSTED)
                stage = "publish-second"
                check(notifications.postRequest(b,30_000) == WakeNotificationResult.POSTED)
                stage = "await-publication"
                withTimeout(5_000) {
                    while (true) {
                        val intents = manager.activeNotifications.map { it.notification.contentIntent }
                        if (pa in intents && pb in intents) break
                        delay(20)
                    }
                }
                withTimeout(15_000) {
                    stage = "first-tap"
                    pa.send(); val initial = first.await(); main = initial
                    val initialOwner = ViewModelProvider(initial)[CommandNavigationViewModel::class.java]
                    initialOwner.navigation.state.first { it.unavailable && it.selected == null }
                    stage = "second-tap"
                    pb.send(); val received = second.await()
                    check(received === initial)
                    check(ViewModelProvider(received)[CommandNavigationViewModel::class.java] === initialOwner)
                    check(received.intent.dataString == b.encode())
                    initialOwner.navigation.state.first { it.unavailable && it.selected == null }
                }
                stage = "await-cancellation"
                notifications.cancelRequest(a);notifications.cancelRequest(b)
                withTimeout(5_000) {
                    while (manager.activeNotifications.any { it.notification.contentIntent == pa || it.notification.contentIntent == pb }) delay(20)
                }
                Log.i(TAG,"{\"probe\":\"notification-navigation-v2\",\"success\":true,\"distinctPendingIntents\":true,\"sameMainActivity\":true,\"sameViewModel\":true,\"unsignedTargetsRejected\":true,\"publishedNotifications\":2,\"clearedNotifications\":true}")
                // Keep the real MainActivity rejection visible for one settled native capture.
                delay(8_000)
            } catch (failure: Exception) {
                Log.e(TAG,"{\"probe\":\"notification-navigation-v2\",\"success\":false,\"failureClass\":\"${failure.javaClass.simpleName}\",\"stage\":\"$stage\"}")
            } finally {
                application.unregisterActivityLifecycleCallbacks(callbacks)
                try { notifications.cancelRequest(a);notifications.cancelRequest(b) } catch (_: Exception) { }
                pa?.cancel();pb?.cancel();main?.finish();finish();probeScope.cancel()
            }
        }
    }
    private companion object { const val TAG = "RemozioNotifyProbe" }
}
