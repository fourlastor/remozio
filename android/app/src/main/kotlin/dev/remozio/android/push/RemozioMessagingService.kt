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
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit

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
        try {
            val manager = WorkManager.getInstance(this)
            val queued = manager.getWorkInfosByTag(WORK_TAG).get(1, TimeUnit.SECONDS)
                .count { !it.state.isFinished }
            if (queued >= MAXIMUM_QUEUED) {
                report(app, generation, PushDeliveryStatus.CAPACITY_LIMIT); return
            }
            val data = workDataOf(GENERATION to generation.toString(), IDENTIFIER to wake.encode()["wake_v1"],
                ENROLLMENT to wake.encode()["enrollment_v1"])
            val request = OneTimeWorkRequestBuilder<FCMWakeWorker>().setInputData(data).addTag(WORK_TAG)
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST).build()
            val tag = MessageDigest.getInstance("SHA-256").digest(wake.enrollmentTag).joinToString("") { "%02x".format(it.toInt() and 255) }
            report(app, generation, PushDeliveryStatus.QUEUED)
            val operation = manager.enqueueUniqueWork("remozio.fcm." + generation + "." + tag, ExistingWorkPolicy.KEEP, request)
            operation.result.addListener({
                try { operation.result.get() } catch (_: Exception) { report(app, generation, PushDeliveryStatus.UNAVAILABLE) }
            }, { it.run() })
        } catch (_: Exception) { report(app, generation, PushDeliveryStatus.UNAVAILABLE) }
    }
    private companion object {
        const val WORK_TAG = "remozio.fcm.ingress.v1"
        const val MAXIMUM_QUEUED = 256
    }
}

/** Local archive and generic notification work only. It never opens a network connection or signs a decision. */
class FCMWakeWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val generation = try { UUID.fromString(inputData.getString(GENERATION)) } catch (_: Exception) { return Result.failure() }
        val identifier = inputData.getString(IDENTIFIER) ?: return Result.failure()
        val enrollment = inputData.getString(ENROLLMENT) ?: return Result.failure()
        val app = applicationContext as RemozioApplication
        val receipt = app.wakeNotifications.receive(generation, mapOf("wake_v1" to identifier, "enrollment_v1" to enrollment))
        report(app, generation, wakeDeliveryStatus(receipt))
        return Result.success()
    }
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

private const val GENERATION = "provider_generation"
private const val IDENTIFIER = "wake"
private const val ENROLLMENT = "enrollment"

private fun report(app: RemozioApplication, generation: UUID, status: PushDeliveryStatus) {
    try { app.pushClient.withCurrent(generation) { app.pushDelivery.record(generation, status) } } catch (_: Exception) { }
}
