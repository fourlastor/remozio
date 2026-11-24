package dev.sebastiano.remozio.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.ViewModelProvider
import dev.sebastiano.remozio.android.enrollment.PairingPhase
import dev.sebastiano.remozio.android.enrollment.PairingSetupSheet
import dev.sebastiano.remozio.android.enrollment.PairingViewModel

/** Debug-only entrance for the v2 setup flow. Accepts no invitation through its intent. */
class PairingV2TestActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val owner = ViewModelProvider(this, PairingViewModel.Factory(application as RemozioApplication))[PairingViewModel::class.java]
        owner.open()
        setContent {
            val state by owner.state.collectAsState()
            LaunchedEffect(state.phase) {
                if (state.phase == PairingPhase.CLOSED) finish()
            }
            RemozioTheme { PairingSetupSheet(owner, this, testV2 = true) }
        }
    }
}
