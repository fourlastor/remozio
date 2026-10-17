package dev.remozio.android.push

import android.content.Context
import android.content.Intent
import androidx.work.*
import com.google.android.gms.cloudmessaging.CloudMessage
import com.google.android.gms.cloudmessaging.Rpc
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import dev.remozio.android.RemozioApplication
import dev.remozio.protocol.PushData
import dev.remozio.phone.push.WakeReceipt
import dev.remozio.phone.push.WakeReception
import dev.remozio.phone.push.WakeNotificationResult
import java.util.UUID

/** Reject provider notification fields before the pinned SDK can render them outside our callback. */
internal fun acceptsFCMExtras(keys: Set<String>): Boolean = keys.none {
    it.startsWith("gcm.n.") || it.startsWith("gcm.notification.")
}

internal fun dispatchFCMIntent(
    action: String?, enabled: Boolean, keys: Set<String>, acknowledgeRejected: () -> Unit, deliver: () -> Unit,
) {
    val delivery = action in setOf("com.google.android.c2dm.intent.RECEIVE", "com.google.firebase.messaging.RECEIVE_DIRECT_BOOT")
    if (delivery && (!enabled || !acceptsFCMExtras(keys))) acknowledgeRejected() else deliver()
}

class RemozioMessagingService : FirebaseMessagingService() {
    private val rejectedDeliveryRPC by lazy { Rpc(applicationContext) }
    override fun handleIntent(intent: Intent) = dispatchFCMIntent(
        intent.action, (application as RemozioApplication).pushClient.generation() != null,
        intent.extras?.keySet().orEmpty(),
        acknowledgeRejected = {
            try { rejectedDeliveryRPC.messageHandled(CloudMessage(intent)) } catch (_: RuntimeException) { }
        },
        deliver = { super.handleIntent(intent) },
    )
    @Suppress("OVERRIDE_DEPRECATION")
    override fun onNewToken(token: String) { (application as RemozioApplication).pushClient.tokenChanged() }
    override fun onMessageReceived(message: RemoteMessage) {
        val app = application as RemozioApplication
        val generation = app.pushClient.generation() ?: return
        if (message.notification != null || !app.pushClient.acceptsSender(message.from)) return
        val wake = try { PushData.decode(message.data) as? PushData.Wake } catch (_: Exception) { null } ?: return
        app.wakeWork.accept(generation, wake)
    }
}

/** Posts the generic alert and commits demand before requesting network work. */
class FCMWakeWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val generation = generation() ?: return Result.failure()
        val identifier = inputData.getString(WAKE_IDENTIFIER) ?: return Result.failure()
        val enrollment = inputData.getString(WAKE_ENROLLMENT) ?: return Result.failure()
        val app = applicationContext as RemozioApplication
        if (app.pushClient.generation() != generation) return Result.success()
        return try {
            val receipt = app.wakeNotifications.receiveAndAdmit(generation,
                mapOf("wake_v1" to identifier, "enrollment_v1" to enrollment))
            report(app, generation, wakeDeliveryStatus(receipt?.receipt))
            when (receipt?.demand) {
                WakeDemandAdmission.NONE -> Result.success()
                WakeDemandAdmission.CHECK_JOURNAL -> if (app.wakeWork.reconcile(generation)) Result.success() else retryBounded(app)
                else -> retryBounded(app)
            }
        } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
        catch (_: Exception) { retryBounded(app) }
    }
}

/** Fetches a complete authenticated snapshot through the foreground connection owner. */
class WakeSnapshotWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val generation = generation() ?: return Result.failure()
        val tag = try {
            val encoded = inputData.getString(WAKE_ENROLLMENT) ?: return Result.failure()
            val dummy = PushData.Wake(ByteArray(32), ByteArray(32)).encode().getValue("wake_v1")
            dev.remozio.protocol.CborValue.Bytes((PushData.decode(mapOf("wake_v1" to dummy, "enrollment_v1" to encoded)) as PushData.Wake).enrollmentTag)
        } catch (_: Exception) { return Result.failure() }
        val app = applicationContext as RemozioApplication
        return try {
            when (app.wakeFetches.fetch(generation, tag)) {
                WakeFetchResult.COMPLETE, WakeFetchResult.OBSOLETE -> Result.success()
                WakeFetchResult.RETRY -> retryBounded(app)
            }
        } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
        catch (_: Exception) { retryBounded(app) }
    }
}

/** Periodic work restores scheduling after an interrupted commit-to-enqueue sequence. */
class WakeReconcileWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val generation = generation() ?: return Result.failure()
        val app = applicationContext as RemozioApplication
        return try {
            if (app.wakeWork.reconcile(generation)) Result.success() else retryBounded(app)
        } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
        catch (_: Exception) { retryBounded(app) }
    }
}
private fun CoroutineWorker.generation(): UUID? = try { UUID.fromString(inputData.getString(WAKE_GENERATION)) } catch (_: Exception) { null }
private fun CoroutineWorker.retryBounded(app: RemozioApplication): androidx.work.ListenableWorker.Result {
    val generation = generation()
    if (generation != null && app.pushClient.generation() != generation) return androidx.work.ListenableWorker.Result.success()
    generation?.let { report(app, it, PushDeliveryStatus.UNAVAILABLE) }
    return if (runAttemptCount + 1 < app.wakeWorkSettings.read().maximumAttempts) androidx.work.ListenableWorker.Result.retry()
        else androidx.work.ListenableWorker.Result.failure()
}

internal fun wakeDeliveryStatus(receipt: WakeReceipt?): PushDeliveryStatus = when (receipt?.notification) {
    WakeNotificationResult.POSTED -> PushDeliveryStatus.ALERT_REQUESTED
    WakeNotificationResult.PERMISSION_DENIED, WakeNotificationResult.APP_DISABLED -> PushDeliveryStatus.PERMISSION_BLOCKED
    WakeNotificationResult.CHANNEL_DISABLED -> PushDeliveryStatus.CHANNEL_BLOCKED
    WakeNotificationResult.FAILED -> PushDeliveryStatus.UNAVAILABLE
    null -> when (receipt?.reception) {
        WakeReception.DUPLICATE, WakeReception.UNKNOWN_ENROLLMENT,
        WakeReception.TOKEN_CHALLENGE, WakeReception.MALFORMED -> PushDeliveryStatus.IGNORED
        else -> PushDeliveryStatus.UNAVAILABLE
    }
}

private fun report(app: RemozioApplication, generation: UUID, status: PushDeliveryStatus) {
    try { app.pushClient.withCurrent(generation) { app.pushDelivery.record(generation, status) } } catch (_: Exception) { }
}
