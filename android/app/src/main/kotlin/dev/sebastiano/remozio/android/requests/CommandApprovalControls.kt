package dev.sebastiano.remozio.android.requests

import androidx.activity.ComponentActivity
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.biometrics.*
import dev.sebastiano.remozio.android.decisions.AndroidDecisionIdentities
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.CommandRequestSession
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.phone.requests.RequestLimits
import dev.remozio.phone.requests.TrackedRequestStatus
import dev.remozio.protocol.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The host supplies a sender bound to this trusted enrollment. Returning means write completion, not Mac acceptance. */
internal class CommandApprovalContext(
    val record: StoredPhoneEnrollment,
    val limits: RequestLimits,
    val send: suspend (ApprovalMessage) -> Unit,
)

internal data class CommandActionAvailability(val execute: Boolean, val decline: Boolean)
internal fun commandActionAvailability(session: CommandRequestSession, record: StoredPhoneEnrollment, now: ElapsedInstant): CommandActionAvailability {
    val enrollment = record.enrollment
    if (record.phase != EnrollmentPhase.ACTIVE || !session.isBoundToAuthority(enrollment.macID.copyBytes(),
            enrollment.accountID.copyBytes(), enrollment.authorityPublicKey.copyBytes())) return CommandActionAvailability(false, false)
    fun allowed(choice: ActionChoice, key: EnrollmentKeyReference) = try {
        session.withPendingDecision(now, enrollment.phoneID.copyBytes(), key.keyID.copyBytes(),
            CapturedAction(choice, ActionScope.CurrentRequest)) { true }
    } catch (_: Exception) { false }
    return CommandActionAvailability(allowed(ActionChoice.EXECUTE, enrollment.biometricKey),
        allowed(ActionChoice.DECLINE, enrollment.decisionKey))
}

internal enum class CommandActionStage { IDLE, PREPARING, BIOMETRIC, SENDING, AWAITING, UNAVAILABLE, UNCERTAIN }

/** All state is in memory. Tickets reject work and callbacks from replaced or stopped views. */
internal class CommandActionAttempt {
    private var ticket: Any? = null
    fun begin(): Any = Any().also { ticket = it }
    fun owns(value: Any) = ticket === value
    fun invalidate() { ticket = null }
}

internal class CommandApprovalViewState {
    val attempts = CommandActionAttempt()
    var stage by mutableStateOf(CommandActionStage.IDLE)
    var retained by mutableStateOf<ApprovalMessage?>(null)
    fun clear() { attempts.invalidate(); retained = null; stage = CommandActionStage.IDLE }
}

@Composable
internal fun CommandApprovalControls(session: CommandRequestSession, context: CommandApprovalContext, status: TrackedRequestStatus?, state: CommandApprovalViewState) {
    if (status?.status?.phase !in setOf(RequestPhase.QUEUED, RequestPhase.PRESENTED)) return
    val activity = LocalActivity.current as? ComponentActivity
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val scope = rememberCoroutineScope()
    key(session, context.record, context.limits, lifecycle) {
        val sender by rememberUpdatedState(context.send)
        val attempts = state.attempts
        var prompt by remember { mutableStateOf<CommandBiometricPrompt?>(null) }
        var job by remember { mutableStateOf<Job?>(null) }
        var foreground by remember { mutableStateOf(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }
        val availability = commandActionAvailability(session, context.record, RequestElapsedClock.now())

        fun stop() {
            attempts.invalidate()
            job?.cancel(); job = null
            prompt?.close(); prompt = null
            state.stage = if (state.retained != null) CommandActionStage.UNCERTAIN else CommandActionStage.IDLE
        }
        DisposableEffect(session, context.record, context.limits, lifecycle) {
            val observer = LifecycleEventObserver { _, event ->
                foreground = lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
                if (event == Lifecycle.Event.ON_STOP) stop()
            }
            lifecycle.addObserver(observer)
            onDispose { lifecycle.removeObserver(observer); stop() }
        }

        fun deliver(ticket: Any, message: ApprovalMessage) {
            if (!attempts.owns(ticket)) return
            state.retained = message
            state.stage = CommandActionStage.SENDING
            job = scope.launch {
                try {
                    sender(message)
                    if (attempts.owns(ticket)) state.stage = CommandActionStage.AWAITING
                } catch (cancelled: CancellationException) {
                    if (attempts.owns(ticket)) state.stage = CommandActionStage.UNCERTAIN
                    throw cancelled
                } catch (_: Exception) { if (attempts.owns(ticket)) state.stage = CommandActionStage.UNCERTAIN }
            }
        }

        fun decide(execute: Boolean) {
            if (!foreground || activity == null || state.retained != null ||
                state.stage !in setOf(CommandActionStage.IDLE, CommandActionStage.UNAVAILABLE)) return
            val ticket = attempts.begin()
            state.stage = CommandActionStage.PREPARING
            job = scope.launch {
                try {
                    if (execute) {
                        var loaded: AndroidCommandBiometrics? = null
                        try {
                            withContext(Dispatchers.IO) {
                                loaded = AndroidCommandBiometrics.load(context.record, session, context.limits, RequestElapsedClock::now)
                            }
                            if (!attempts.owns(ticket)) return@launch
                            val native = CommandBiometricPrompt(activity, checkNotNull(loaded))
                            loaded = null
                            prompt = native
                            state.stage = CommandActionStage.BIOMETRIC
                            native.authenticate { result ->
                                native.close()
                                if (!attempts.owns(ticket)) return@authenticate
                                prompt = null
                                when (result) {
                                    is CommandBiometricResult.Signed -> deliver(ticket, result.message)
                                    CommandBiometricResult.Cancelled -> state.stage = CommandActionStage.IDLE
                                    CommandBiometricResult.Unavailable -> state.stage = CommandActionStage.UNAVAILABLE
                                }
                            }
                        } finally { loaded?.close() }
                    } else {
                        val message = withContext(Dispatchers.IO) {
                            AndroidDecisionIdentities.load(context.record).use {
                                it.declineSession(session, RequestElapsedClock.now(), context.limits)
                            }
                        }
                        deliver(ticket, message)
                    }
                } catch (cancelled: CancellationException) {
                    if (attempts.owns(ticket)) state.stage = CommandActionStage.UNAVAILABLE
                    throw cancelled
                } catch (_: Exception) { if (attempts.owns(ticket)) state.stage = CommandActionStage.UNAVAILABLE }
            }
        }

        val busy = state.stage in setOf(CommandActionStage.PREPARING, CommandActionStage.BIOMETRIC, CommandActionStage.SENDING)
        val mayChoose = !busy && state.retained == null && foreground && activity != null
        val height = with(LocalDensity.current) { LocalWindowInfo.current.containerSize.height.toDp() / 2 }
        Column(Modifier.fillMaxWidth().heightIn(max = height).verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            val label = when (state.stage) {
                CommandActionStage.IDLE -> null
                CommandActionStage.PREPARING -> R.string.command_action_preparing
                CommandActionStage.BIOMETRIC -> R.string.command_action_biometric
                CommandActionStage.SENDING -> R.string.command_action_sending
                CommandActionStage.AWAITING -> R.string.command_action_awaiting
                CommandActionStage.UNAVAILABLE -> R.string.command_action_unavailable
                CommandActionStage.UNCERTAIN -> R.string.command_action_uncertain
            }
            if (label != null) Text(stringResource(label), style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            if (availability.execute) Button(onClick = { decide(true) }, enabled = mayChoose, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.command_action_approve))
            }
            if (availability.decline) OutlinedButton(onClick = { decide(false) }, enabled = mayChoose, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.command_action_decline))
            }
            if (state.stage == CommandActionStage.UNCERTAIN && state.retained != null && (availability.execute || availability.decline)) {
                OutlinedButton(onClick = { if (foreground && state.stage == CommandActionStage.UNCERTAIN)
                    state.retained?.let { deliver(attempts.begin(), it) } },
                    enabled = foreground, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.command_action_retry)) }
            }
        }
    }
}
