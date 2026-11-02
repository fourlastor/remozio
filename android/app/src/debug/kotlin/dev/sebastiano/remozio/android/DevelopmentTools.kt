package dev.sebastiano.remozio.android

import android.content.Intent
import androidx.compose.ui.platform.LocalContext
import dev.remozio.phone.requests.RequestTiming
import dev.remozio.phone.requests.TrackedRequestStatus

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import dev.sebastiano.remozio.android.requests.CommandInspection
import dev.remozio.protocol.CborLimits
import dev.remozio.protocol.CommandCapture
import dev.remozio.protocol.RequestPhase
import dev.remozio.protocol.RequestStatusPayload
import dev.remozio.protocol.RequestStatusReason

private enum class SampleScene(val label: Int) {
    PENDING(R.string.open_sample_command),
    STREAMS(R.string.open_sample_streams),
    PIPES(R.string.open_sample_pipes),
    FLAGS(R.string.open_sample_flags),
    ESTIMATE_PASSED(R.string.open_sample_estimate),
    EXPIRED(R.string.open_sample_expired),
    DISAPPEARED(R.string.open_sample_disappeared),
    UNKNOWN(R.string.open_sample_unknown),
    CLOCK_UNCERTAIN(R.string.open_sample_clock),
}

@Composable
internal fun DevelopmentTools() {
    var scene by remember { mutableStateOf<SampleScene?>(null) }
    val context = LocalContext.current
    Column {
        OutlinedButton(onClick = { context.startActivity(Intent(context, AdbEndpointProbeActivity::class.java)) }) {
            Text(stringResource(R.string.adb_probe_title))
        }
        OutlinedButton(onClick = { context.startActivity(Intent(context, BiometricProbeActivity::class.java)) }) {
            Text(stringResource(R.string.probe_title))
        }
        SampleScene.entries.forEach { sample ->
            OutlinedButton(onClick = { scene = sample }) { Text(stringResource(sample.label)) }
        }
    }
    val current = scene ?: return
    val resources = LocalResources.current
    val status = remember(current) { sampleStatus(current) }
    val capture = remember(current, resources) {
        val (resource, schema) = when (current) {
            SampleScene.PENDING, SampleScene.CLOCK_UNCERTAIN -> R.raw.sample_command to 1uL
            SampleScene.STREAMS -> R.raw.sample_command_streams to 3uL
            SampleScene.PIPES -> R.raw.sample_command_pipes to 3uL
            SampleScene.FLAGS -> R.raw.sample_command_flags to 3uL
            else -> return@remember null
        }
        val bytes = resources.openRawResource(resource).use { it.readBytes() }
        CommandCapture(bytes, CborLimits(8192, 16, 1024), expectedSchemaVersion = schema)
    }
    CommandInspection(capture, stringResource(R.string.sample_mac), stringResource(R.string.sample_account),
        onDismiss = { scene = null }, sample = true, status = status)
}

/** Static display fixtures. They never enter the verifier, tracker, or a transport. */
private fun sampleStatus(scene: SampleScene): TrackedRequestStatus {
    val phase = when (scene) {
        SampleScene.EXPIRED -> RequestPhase.EXPIRED
        SampleScene.DISAPPEARED -> RequestPhase.CANCELLED
        SampleScene.UNKNOWN -> RequestPhase.UNKNOWN
        else -> RequestPhase.PRESENTED
    }
    val reason = when (scene) {
        SampleScene.EXPIRED -> RequestStatusReason.AUTHORIZATION_EXPIRED
        SampleScene.DISAPPEARED -> RequestStatusReason.TARGET_DISAPPEARED
        SampleScene.UNKNOWN -> RequestStatusReason.OUTCOME_UNAVAILABLE
        else -> RequestStatusReason.NONE
    }
    val age = if (scene == SampleScene.ESTIMATE_PASSED) 70_000uL else 24_000uL
    val remaining = if (phase.isTerminal) null else 36_000uL
    val estimate = if (scene == SampleScene.ESTIMATE_PASSED) 60_000uL else null
    val id = ByteArray(16) { 1 }
    val status = RequestStatusPayload(id, id, id, ByteArray(32) { 2 }, ByteArray(32) { 3 }, 1u,
        phase, reason, id, age, remaining, estimate, false, if (phase.isTerminal) age else null,
        if (scene == SampleScene.UNKNOWN) ByteArray(16) { 4 } else null)
    return TrackedRequestStatus(status, RequestTiming(age, remaining,
        if (estimate == null) null else 0u, scene == SampleScene.CLOCK_UNCERTAIN))
}
