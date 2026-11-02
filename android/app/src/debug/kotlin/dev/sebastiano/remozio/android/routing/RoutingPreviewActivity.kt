package dev.sebastiano.remozio.android.routing

import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import dev.remozio.protocol.RoutingStatusDestination
import dev.remozio.protocol.RoutingStatusMode
import dev.remozio.protocol.RoutingStatusReason

/** Static display models only. No pairing, keys, host connection or routing operation. */
open class RoutingPreviewActivity : ComponentActivity() {
    protected enum class Scene { PRESENT, OFFLINE, INCOMPATIBLE, CONFLICT, UNCERTAIN, BUSY }
    protected open val scene = Scene.PRESENT
    protected open val dark = false
    protected open val largeFont = false
    protected open val expanded = false
    protected open val settings = false
    protected open val scrollToEnd = false
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        if (dark) enableEdgeToEdge(statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)) else enableEdgeToEdge()
        if (expanded) requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
        setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, if (largeFont) 2f else density.fontScale)) {
                RemozioTheme(darkTheme = dark) {
                    val scroll = rememberScrollState()
                    LaunchedEffect(scroll.maxValue) {
                        if (scrollToEnd && scroll.maxValue in 1 until Int.MAX_VALUE) scroll.scrollTo(scroll.maxValue)
                    }
                    RemozioNavigation(if (settings) 3 else 1, {}) {
                        Column(Modifier.fillMaxSize()) {
                            Text(stringResource(R.string.routing_preview_notice), style = MaterialTheme.typography.bodySmall)
                            Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(scroll).padding(24.dp),
                                horizontalAlignment = Alignment.CenterHorizontally) {
                                Column(Modifier.widthIn(max = 720.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(24.dp)) {
                                    Text(stringResource(if (settings) R.string.nav_settings else R.string.your_macs),
                                        style = MaterialTheme.typography.headlineLarge, modifier = Modifier.semantics { heading() })
                                    if (settings) RoutingWorkSettingsCard(initiallyExpanded = true)
                                    else {
                                        PreviewCard(scene, R.string.routing_preview_studio)
                                        if (scene == Scene.PRESENT && !largeFont && !expanded) PreviewCard(Scene.OFFLINE, R.string.routing_preview_laptop)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    @Composable
    private fun PreviewCard(scene: Scene, label: Int) {
        val availability = when (scene) {
            Scene.OFFLINE -> MacRoutingAvailability.OFFLINE
            Scene.INCOMPATIBLE -> MacRoutingAvailability.INCOMPATIBLE
            else -> MacRoutingAvailability.ONLINE
        }
        val current = availability == MacRoutingAvailability.ONLINE
        val action = when (scene) {
            Scene.CONFLICT -> MacRoutingAction.CONFLICT
            Scene.UNCERTAIN -> MacRoutingAction.UNCERTAIN
            Scene.BUSY -> MacRoutingAction.SETTING_AWAY
            else -> MacRoutingAction.IDLE
        }
        val model = MacRoutingDisplay(availability, if (current) RoutingStatusMode.PRESENT else null,
            if (current) null else RoutingStatusMode.AWAY, if (current) RoutingStatusDestination.LOCAL_MAC else null,
            if (current) RoutingStatusReason.MANUAL_PRESENT else null, false, if (current) 3000 else 93_000,
            action, current && scene != Scene.BUSY)
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(label), style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
                RoutingStatusContent(model, working = scene == Scene.BUSY, refreshing = false, incomplete = false,
                    onSetAway = {}, onRefresh = {})
            }
        }
    }
}
class RoutingDarkPreviewActivity : RoutingPreviewActivity() { override val dark = true }
class RoutingLargeFontPreviewActivity : RoutingPreviewActivity() { override val largeFont = true }
class RoutingExpandedPreviewActivity : RoutingPreviewActivity() { override val expanded = true }
class RoutingExpandedDarkPreviewActivity : RoutingPreviewActivity() { override val expanded = true; override val dark = true }
class RoutingOfflinePreviewActivity : RoutingPreviewActivity() { override val scene = Scene.OFFLINE }
class RoutingIncompatiblePreviewActivity : RoutingPreviewActivity() { override val scene = Scene.INCOMPATIBLE }
class RoutingConflictPreviewActivity : RoutingPreviewActivity() { override val scene = Scene.CONFLICT }
class RoutingUncertainPreviewActivity : RoutingPreviewActivity() { override val scene = Scene.UNCERTAIN }
class RoutingBusyPreviewActivity : RoutingPreviewActivity() { override val scene = Scene.BUSY }
class RoutingSettingsPreviewActivity : RoutingPreviewActivity() { override val settings = true }
class RoutingSettingsDarkPreviewActivity : RoutingPreviewActivity() { override val settings = true; override val dark = true }
class RoutingSettingsLargeFontPreviewActivity : RoutingPreviewActivity() { override val settings = true; override val largeFont = true }

class RoutingSettingsLargeFontEndPreviewActivity : RoutingPreviewActivity() { override val settings = true; override val largeFont = true; override val scrollToEnd = true }
class RoutingExpandedActionsPreviewActivity : RoutingPreviewActivity() { override val expanded = true; override val scrollToEnd = true }
class RoutingExpandedDarkActionsPreviewActivity : RoutingPreviewActivity() { override val expanded = true; override val dark = true; override val scrollToEnd = true }
