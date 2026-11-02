package dev.remozio.android.audit

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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
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
import dev.remozio.android.R
import dev.remozio.android.RemozioNavigation
import dev.remozio.android.RemozioTheme

/** Static display models. Does not read preferences, save settings, open keys or start synchronization. */
open class AuditWorkSettingsPreviewActivity : ComponentActivity() {
    protected enum class Scene { COLLAPSED, EDIT, INVALID, SAVING, FAILED, SAVED, DEFAULTS }
    protected open val scene = Scene.EDIT
    protected open val dark = false
    protected open val largeFont = false
    protected open val expanded = false
    protected open val scrollToEnd = false
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        setTurnScreenOn(true)
        setShowWhenLocked(true)
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
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
                    RemozioNavigation(3, {}) {
                        Column(Modifier.fillMaxSize()) {
                            Text(stringResource(R.string.audit_settings_preview_notice), style = MaterialTheme.typography.bodySmall)
                            Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(scroll).padding(24.dp),
                                horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
                                Text(stringResource(R.string.nav_settings), style = MaterialTheme.typography.headlineLarge,
                                    modifier = Modifier.semantics { heading() })
                                val saved = if (scene in setOf(Scene.SAVED, Scene.DEFAULTS)) AuditWorkPolicy(64, 45) else AuditWorkPolicy()
                                val fields = when (scene) {
                                    Scene.INVALID -> listOf("0", "61")
                                    Scene.DEFAULTS, Scene.COLLAPSED -> listOf("32", "30")
                                    else -> listOf("64", "45")
                                }
                                val result = when (scene) {
                                    Scene.FAILED -> AuditSettingsResult.FAILED
                                    Scene.SAVED -> AuditSettingsResult.SAVED
                                    else -> null
                                }
                                AuditWorkSettingsContent(saved, fields, scene != Scene.COLLAPSED, scene == Scene.SAVING,
                                    result, {}, {}, {}, {})
                            }
                        }
                    }
                }
            }
        }
    }
}
class AuditSettingsCollapsedPreviewActivity : AuditWorkSettingsPreviewActivity() { override val scene = Scene.COLLAPSED }
class AuditSettingsDarkPreviewActivity : AuditWorkSettingsPreviewActivity() { override val dark = true }
class AuditSettingsLargeFontPreviewActivity : AuditWorkSettingsPreviewActivity() { override val largeFont = true }
class AuditSettingsLargeFontEndPreviewActivity : AuditWorkSettingsPreviewActivity() { override val largeFont = true; override val scrollToEnd = true }
class AuditSettingsExpandedPreviewActivity : AuditWorkSettingsPreviewActivity() { override val expanded = true }
class AuditSettingsExpandedEndPreviewActivity : AuditWorkSettingsPreviewActivity() { override val expanded = true; override val scrollToEnd = true }
class AuditSettingsExpandedDarkPreviewActivity : AuditWorkSettingsPreviewActivity() { override val expanded = true; override val dark = true }
class AuditSettingsExpandedDarkEndPreviewActivity : AuditWorkSettingsPreviewActivity() { override val expanded = true; override val dark = true; override val scrollToEnd = true }
class AuditSettingsInvalidPreviewActivity : AuditWorkSettingsPreviewActivity() { override val scene = Scene.INVALID; override val scrollToEnd = true }
class AuditSettingsSavingPreviewActivity : AuditWorkSettingsPreviewActivity() { override val scene = Scene.SAVING; override val scrollToEnd = true }
class AuditSettingsFailedPreviewActivity : AuditWorkSettingsPreviewActivity() { override val scene = Scene.FAILED; override val scrollToEnd = true }
class AuditSettingsSavedPreviewActivity : AuditWorkSettingsPreviewActivity() { override val scene = Scene.SAVED; override val scrollToEnd = true }
class AuditSettingsDefaultsPreviewActivity : AuditWorkSettingsPreviewActivity() { override val scene = Scene.DEFAULTS; override val scrollToEnd = true }
