package dev.sebastiano.remozio.android.updates

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import dev.sebastiano.remozio.android.R
import kotlinx.coroutines.CancellationException
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The user opens this private activity through an immutable confirmation capability. */
class UpdateConfirmationActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val binding = if (intent.action == UPDATE_CONFIRM_ACTION) UpdateCallbackBinding.parse(intent.dataString) else null
        val confirmation = runCatching { intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java) }.getOrNull()
        if (binding == null || confirmation == null || savedInstanceState?.getBoolean("opened") == true) {
            finish()
            return
        }
        lifecycleScope.launch {
            try {
                val valid = withContext(Dispatchers.IO) {
                    openUpdateRecords(applicationContext).use { store ->
                        store.snapshot()?.let { binding.matches(it) && it.packageName == packageName &&
                            it.phase == UpdatePhase.AWAITING_USER } == true
                    }
                }
                if (valid) {
                    opened = true
                    startActivity(confirmation)
                } else unavailable()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                unavailable()
            } finally { finish() }
        }
    }

    private fun unavailable() {
        Toast.makeText(this, R.string.update_confirmation_unavailable, Toast.LENGTH_LONG).show()
    }

    private var opened = false
    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean("opened", opened)
        super.onSaveInstanceState(outState)
    }
}
