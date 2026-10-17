package dev.remozio.android.push

import android.os.Bundle
import android.content.pm.ApplicationInfo
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.remozio.android.RemozioTheme
import dev.remozio.android.R
import kotlinx.coroutines.delay

/** Debug-only routes render the actual cards. They create no enrollment or provider configuration. */
open class RegistrationLayoutPreviewActivity : ComponentActivity() {
    protected open val limits = false
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        enableEdgeToEdge()
        setContent { RemozioTheme {
            Surface(Modifier.fillMaxSize()) {
                val scroll = rememberScrollState()
                if (limits) LaunchedEffect(Unit) { delay(10_000); scroll.animateScrollTo(scroll.maxValue) }
                Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(scroll).padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(stringResource(R.string.nav_settings), style = MaterialTheme.typography.headlineLarge,
                        modifier = Modifier.semantics { heading() })
                    if (limits) PushRegistrationWorkSettingsCard(initiallyExpanded = true)
                    else PushRegistrationStatusCard()
                }
            }
        } }
    }
}
class RegistrationStatusPreviewActivity : RegistrationLayoutPreviewActivity()
class RegistrationLimitsPreviewActivity : RegistrationLayoutPreviewActivity() { override val limits = true }
