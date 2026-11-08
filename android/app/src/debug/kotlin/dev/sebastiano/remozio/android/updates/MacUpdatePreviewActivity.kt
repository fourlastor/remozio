package dev.sebastiano.remozio.android.updates

import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.RemozioNavigation
import dev.sebastiano.remozio.android.RemozioTheme
import dev.sebastiano.remozio.android.routing.MacRoutingAction
import dev.sebastiano.remozio.android.routing.MacRoutingAvailability
import dev.sebastiano.remozio.android.routing.MacRoutingDisplay
import dev.sebastiano.remozio.android.routing.RoutingStatusContent
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.RoutingStatusDestination
import dev.remozio.protocol.RoutingStatusMode
import dev.remozio.protocol.RoutingStatusReason
import dev.remozio.protocol.UpdateSchedulingAction
import dev.remozio.protocol.UpdateSchedulingAdmissionState
import dev.remozio.protocol.UpdateSchedulingBlocker
import dev.remozio.protocol.UpdateSchedulingDesignation
import dev.remozio.protocol.UpdateSchedulingProgressPhase
import dev.remozio.protocol.UpdateSchedulingProgressResponse
import dev.remozio.protocol.UpdateSchedulingSecurityStatus
import dev.remozio.protocol.UpdateSchedulingStatusResponse

/**
 * Static display models only. No pairing, keys, host connection or scheduling operation.
 * Extras: `scene` (a [Scene] name), `dark`, `largeFont` and `end` (scroll to the end).
 */
class MacUpdatePreviewActivity : ComponentActivity() {
    private enum class Scene { READY, DRAINING, LOADING, UNAVAILABLE, LAST_KNOWN, TOO_LATE, SENDING, UNCERTAIN, FAILED }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        val scene = intent.getStringExtra("scene")?.let(Scene::valueOf) ?: Scene.READY
        val dark = intent.getBooleanExtra("dark", false)
        val largeFont = intent.getBooleanExtra("largeFont", false)
        val end = intent.getBooleanExtra("end", false)
        if (dark) enableEdgeToEdge(statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)) else enableEdgeToEdge()
        setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, if (largeFont) 2f else density.fontScale)) {
                RemozioTheme(darkTheme = dark) {
                    val scroll = rememberScrollState()
                    LaunchedEffect(scroll.maxValue) {
                        if (end && scroll.maxValue in 1 until Int.MAX_VALUE) scroll.scrollTo(scroll.maxValue)
                    }
                    RemozioNavigation(1, {}) {
                        Column(Modifier.fillMaxSize()) {
                            Text(stringResource(R.string.mac_update_preview_notice), style = MaterialTheme.typography.bodySmall)
                            Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(scroll).padding(24.dp),
                                horizontalAlignment = Alignment.CenterHorizontally) {
                                Column(Modifier.widthIn(max = 720.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(24.dp)) {
                                    Text(stringResource(R.string.your_macs), style = MaterialTheme.typography.headlineLarge,
                                        modifier = Modifier.semantics { heading() })
                                    Card(Modifier.fillMaxWidth()) {
                                        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                            Text(stringResource(R.string.routing_preview_studio), style = MaterialTheme.typography.titleLarge,
                                                modifier = Modifier.semantics { heading() })
                                            if (!largeFont) {
                                                RoutingStatusContent(routing(), working = false, refreshing = false, incomplete = false,
                                                    onSetAway = {}, onRefresh = {})
                                                HorizontalDivider(Modifier.padding(vertical = 8.dp))
                                            }
                                            when (scene) {
                                                Scene.LOADING -> MacUpdateLoading()
                                                Scene.UNAVAILABLE -> MacUpdateUnavailable(onRetry = {})
                                                else -> MacUpdateStatusBody(display(scene), checking = scene == Scene.SENDING,
                                                    userRefreshing = false, working = scene == Scene.SENDING, incomplete = false,
                                                    onRefresh = {}, onSchedule = {}, initiallyShowDetails = scene == Scene.DRAINING)
                                            }
                                            TextButton(onClick = {}) { Text(stringResource(R.string.commands_open)) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun routing() = MacRoutingDisplay(MacRoutingAvailability.ONLINE, RoutingStatusMode.PRESENT, null,
        RoutingStatusDestination.LOCAL_MAC, RoutingStatusReason.MANUAL_PRESENT, false, 3000, MacRoutingAction.IDLE, true)

    private fun display(scene: Scene): MacUpdateDisplay {
        val ready = frame(UpdateSchedulingProgressPhase.READY, UpdateSchedulingAdmissionState.OPEN, null, 3uL,
            UpdateSchedulingSecurityStatus.SECURITY, READY_AGE)
        val readyOnly = frame(UpdateSchedulingProgressPhase.READY, UpdateSchedulingAdmissionState.OPEN, null, 0uL,
            UpdateSchedulingSecurityStatus.SECURITY, READY_AGE)
        return when (scene) {
            Scene.READY -> MacUpdateDisplay(ready, null, 20_000, READY_AGE, emptyList(), null, tooLate = false,
                canInstall = true, canDefer = true, canCancelDrain = false)
            Scene.DRAINING -> {
                val blockers = listOf(
                    UpdateSchedulingBlocker(UpdateSchedulingBlocker.Kind.PENDING_REQUESTS, 2u, 300_000u),
                    UpdateSchedulingBlocker(UpdateSchedulingBlocker.Kind.ACTIVE_COMMANDS, 1u, 2_520_000u),
                    UpdateSchedulingBlocker(UpdateSchedulingBlocker.Kind.LIVE_GUI_PERMITS, 1u, 30_000u),
                    UpdateSchedulingBlocker(UpdateSchedulingBlocker.Kind.OTHER_ACCOUNTS, null, null),
                )
                val draining = frame(UpdateSchedulingProgressPhase.DRAINING, UpdateSchedulingAdmissionState.CLOSED,
                    UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES, 4uL, UpdateSchedulingSecurityStatus.NOT_SECURITY,
                    READY_AGE, blockers)
                MacUpdateDisplay(draining, null, 45_000, READY_AGE,
                    blockers.map { MacUpdateBlockerDisplay(it.kind, it.count, it.oldestAgeMilliseconds) },
                    attempt(UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES, MacUpdateSchedulingOutcome.ACKNOWLEDGED),
                    tooLate = false, canInstall = false, canDefer = false, canCancelDrain = true)
            }
            Scene.LAST_KNOWN -> MacUpdateDisplay(null, readyOnly, 10_800_000, READY_AGE, emptyList(), null, tooLate = false,
                canInstall = false, canDefer = false, canCancelDrain = false)
            Scene.TOO_LATE -> MacUpdateDisplay(frame(UpdateSchedulingProgressPhase.ACTIVATING, UpdateSchedulingAdmissionState.CLOSED,
                UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES, 0uL, UpdateSchedulingSecurityStatus.SECURITY, READY_AGE),
                null, 5_000, READY_AGE, emptyList(), attempt(UpdateSchedulingAction.CANCEL_DRAIN, MacUpdateSchedulingOutcome.FAILED),
                tooLate = true, canInstall = false, canDefer = false, canCancelDrain = false)
            Scene.SENDING, Scene.UNCERTAIN, Scene.FAILED -> MacUpdateDisplay(readyOnly, null, 20_000, READY_AGE, emptyList(),
                attempt(UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES, when (scene) {
                    Scene.SENDING -> MacUpdateSchedulingOutcome.SUBMITTING
                    Scene.UNCERTAIN -> MacUpdateSchedulingOutcome.UNCERTAIN
                    else -> MacUpdateSchedulingOutcome.FAILED
                }), tooLate = false, canInstall = false, canDefer = false, canCancelDrain = false)
            Scene.LOADING, Scene.UNAVAILABLE -> error("No display model")
        }
    }

    private fun frame(phase: UpdateSchedulingProgressPhase, admission: UpdateSchedulingAdmissionState,
        requested: UpdateSchedulingAction?, actions: ULong, security: UpdateSchedulingSecurityStatus, readyAge: ULong,
        blockers: List<UpdateSchedulingBlocker> = emptyList()) = UpdateSchedulingProgressResponse(
        UpdateSchedulingStatusResponse(ChannelScope(id(1), id(2), id(3), id(4)), ByteArray(32) { 5 }, UPDATE.copyBytes(), 1u,
            if (requested == null) 0u else 1u, requested),
        phase, UpdateSchedulingDesignation.THIS_ACCOUNT, security, readyAge, actions, blockers, admission)

    private fun attempt(action: UpdateSchedulingAction, outcome: MacUpdateSchedulingOutcome) =
        MacUpdateSchedulingAttempt(UPDATE, 1u, 0u, action, outcome)

    private fun id(n: Int) = ByteArray(16) { n.toByte() }

    private companion object {
        val UPDATE = CborValue.Bytes(ByteArray(32) { 6 })
        const val READY_AGE = 8_100_000uL
    }
}
