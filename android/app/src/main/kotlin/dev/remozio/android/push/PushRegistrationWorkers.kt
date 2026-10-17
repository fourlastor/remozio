package dev.remozio.android.push

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dev.remozio.android.RemozioApplication
import dev.remozio.protocol.PhonePushRecoveryPhase
import java.util.UUID
import kotlinx.coroutines.CancellationException

class PushRegistrationWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val selection = selection() ?: return Result.failure()
        val record = registrationIdentifier(inputData.getString(REGISTRATION_RECORD), 16) ?: return Result.failure()
        val app = applicationContext as RemozioApplication
        return try {
            val result = app.pushRegistrations.run(record, selection.first, selection.second)
            when (result.outcome) {
                PushRegistrationOutcome.OBSOLETE, PushRegistrationOutcome.INCOMPATIBLE -> Result.success()
                PushRegistrationOutcome.ROOT_STATE -> if (result.root?.state?.phase == PhonePushRecoveryPhase.MAPPING_OBSERVED)
                    Result.success() else retryBounded(app, selection)
                else -> retryBounded(app, selection)
            }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { retryBounded(app, selection) }
    }
}

class PushRegistrationReconcileWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val selection = selection() ?: return Result.failure()
        val text = inputData.getString(REGISTRATION_TAG)
        val tag = if (text == null) null else registrationIdentifier(text, 32) ?: return Result.failure()
        val trigger = inputData.getString(REGISTRATION_TRIGGER) ?: "refresh"
        if (trigger !in setOf("changed", "refresh") && registrationIdentifier(trigger, 16) == null) return Result.failure()
        val app = applicationContext as RemozioApplication
        return try {
            if (app.pushRegistrationWork.reconcile(selection.first, selection.second, tag, trigger)) Result.success()
            else retryBounded(app, selection)
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { retryBounded(app, selection) }
    }
}
private fun CoroutineWorker.selection(): Pair<UUID, UUID>? = try {
    UUID.fromString(inputData.getString(REGISTRATION_GENERATION)) to UUID.fromString(inputData.getString(REGISTRATION_REVISION))
} catch (_: Exception) { null }
private fun CoroutineWorker.retryBounded(app: RemozioApplication, selection: Pair<UUID, UUID>): androidx.work.ListenableWorker.Result {
    val candidate = app.pushClient.tokenCandidate()
    if (candidate?.generation != selection.first || candidate.revision != selection.second) return androidx.work.ListenableWorker.Result.success()
    return if (runAttemptCount + 1 < app.pushRegistrationWorkSettings.read().maximumAttempts) androidx.work.ListenableWorker.Result.retry()
        else androidx.work.ListenableWorker.Result.failure()
}
