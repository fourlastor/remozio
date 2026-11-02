package dev.sebastiano.remozio.android

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.os.CancellationSignal
import android.security.KeyStoreException
import android.security.keystore.UserNotAuthenticatedException
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import java.security.SecureRandom
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Manual, synthetic signing experiment. Never receives a Remozio approval request. */
class BiometricProbeActivity : ComponentActivity() {
    private val operation = ProbeOperation()
    private var cancellation: CancellationSignal? = null
    private var busy by mutableStateOf(false)
    private var result by mutableStateOf("")
    private var foreground = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        result = getString(R.string.probe_initial)
        setContent {
            RemozioTheme {
                Scaffold { insets ->
                    Column(Modifier.fillMaxSize().padding(insets)
                        .verticalScroll(rememberScrollState()).padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        Text(stringResource(R.string.probe_title), style = MaterialTheme.typography.headlineLarge)
                        Text(stringResource(R.string.probe_description))
                        Text(result)
                        Button(enabled = !busy, onClick = { runKey { BiometricProbeKey.create() } }) {
                            Text(stringResource(R.string.probe_create))
                        }
                        Button(enabled = !busy, onClick = { runKey { BiometricProbeKey.inspect() } }) {
                            Text(stringResource(R.string.probe_inspect))
                        }
                        Button(enabled = !busy, onClick = ::authenticate) { Text(stringResource(R.string.probe_sign)) }
                        Button(enabled = !busy, onClick = ::withoutPrompt) { Text(stringResource(R.string.probe_without)) }
                        Button(enabled = !busy, onClick = { runKey {
                            BiometricProbeKey.delete()
                            getString(R.string.probe_deleted)
                        } }) { Text(stringResource(R.string.probe_delete)) }
                        Button(onClick = { finish() }) { Text(stringResource(R.string.probe_close)) }
                    }
                }
            }
        }
    }

    override fun onStart() { super.onStart(); foreground = true }

    override fun onStop() {
        foreground = false
        operation.invalidate()
        cancellation?.cancel()
        cancellation = null
        busy = false
        result = getString(R.string.probe_stopped)
        super.onStop()
    }

    private fun start(): Any {
        busy = true
        result = getString(R.string.probe_working)
        return operation.begin()
    }

    private fun complete(token: Any, message: String) {
        if (foreground && operation.complete(token)) {
            busy = false
            cancellation = null
            result = message
        }
    }

    private fun failure(token: Any, error: Exception) {
        // Provider messages are deliberately excluded from the display and logs.
        val message = if (error is BiometricProbePolicyException) {
            getString(R.string.probe_policy_error, error.policy.diagnostic())
        } else {
            getString(R.string.probe_error, error.javaClass.simpleName)
        }
        complete(token, message)
    }

    private fun runKey(block: () -> String) {
        val token = start()
        lifecycleScope.launch {
            try { complete(token, withContext(BiometricProbeKey.worker) { block() }) }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (error: Exception) { failure(token, error) }
        }
    }

    private fun withoutPrompt() = runKey {
        try {
            BiometricProbeKey.signature().apply { update(challenge()) }.sign()
            getString(R.string.probe_unprotected)
        } catch (error: Exception) {
            if (!hasAuthenticationCause(error) { cause ->
                cause is UserNotAuthenticatedException ||
                    (cause is KeyStoreException && cause.numericErrorCode ==
                        KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED)
            }) throw error
            getString(R.string.probe_denied)
        }
    }

    private fun challenge(): ByteArray = "Remozio disposable biometric probe v1\u0000".toByteArray(Charsets.UTF_8) +
        ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun authenticate() {
        val token = start()
        val bytes = challenge()
        lifecycleScope.launch {
            try {
                val signature = withContext(BiometricProbeKey.worker) { BiometricProbeKey.signature() }
                if (!foreground || !operation.owns(token)) return@launch
                val signal = CancellationSignal().also { cancellation = it }
                val prompt = BiometricPrompt.Builder(this@BiometricProbeActivity)
                    .setTitle(getString(R.string.probe_prompt_title))
                    .setSubtitle(getString(R.string.probe_prompt_subtitle))
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButton(getString(R.string.probe_cancel), mainExecutor) { _, _ ->
                        complete(token, getString(R.string.probe_cancelled))
                    }.build()
                prompt.authenticate(BiometricPrompt.CryptoObject(signature), signal, mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(auth: BiometricPrompt.AuthenticationResult) {
                            if (!foreground || !operation.owns(token)) return
                            try {
                                check(auth.authenticationType == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC)
                                check(auth.cryptoObject?.signature === signature)
                                // Main-thread callback and onStop cannot interleave this immutable operation.
                                signature.update(bytes)
                                val signed = signature.sign()
                                check(BiometricProbeKey.verify(bytes, signed))
                                complete(token, getString(R.string.probe_signed, signed.size))
                            } catch (error: Exception) { failure(token, error) }
                        }
                        override fun onAuthenticationError(code: Int, text: CharSequence) {
                            complete(token, getString(R.string.probe_auth_error, code))
                        }
                    })
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (error: Exception) { failure(token, error) }
        }
    }
}
