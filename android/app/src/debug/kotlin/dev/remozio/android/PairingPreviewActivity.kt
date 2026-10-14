package dev.remozio.android

import android.os.Bundle
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.*
import kotlinx.coroutines.delay
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import dev.remozio.android.enrollment.PairingPhase
import dev.remozio.android.enrollment.PairingScreenState
import dev.remozio.android.enrollment.PairingSetupSurface

/** Debug display fixtures. This activity never constructs a setup owner, reads storage, or creates keys. */
class PairingPreviewActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val phase = when (intent.getStringExtra("scene")) {
            "compare" -> PairingPhase.COMPARING
            "expired-after-biometric" -> PairingPhase.BIOMETRIC
            "waiting" -> PairingPhase.CONNECTING
            "expired" -> PairingPhase.EXPIRED
            "incomplete" -> PairingPhase.FAILED
            else -> PairingPhase.INPUT
        }
        val state = PairingScreenState(phase = phase, phoneSuffix = "C4D8E012",
            comparisonCode = "37MRQ S9XSE 3EMYL 7QA8F", expiresElapsedMillis = SystemClock.elapsedRealtime() + if (phase == PairingPhase.BIOMETRIC) 1000 else 60_000,
            mayHaveSavedSetup = phase == PairingPhase.FAILED)
        setContent {
            RemozioTheme {
                Surface(color = MaterialTheme.colorScheme.background) {
                    var displayed by remember { mutableStateOf(state) }
                    if (phase == PairingPhase.BIOMETRIC) LaunchedEffect(Unit) {
                        delay(1500)
                        displayed = displayed.copy(phase = PairingPhase.COMPARING)
                    }
                    PairingSetupSurface(displayed, onConnect = {}, onCompare = {}, onExpire = {
                        if (displayed.phase == PairingPhase.COMPARING) displayed = displayed.copy(phase = PairingPhase.EXPIRED)
                    }, onClose = ::finish, preview = true)
                }
            }
        }
    }
}
