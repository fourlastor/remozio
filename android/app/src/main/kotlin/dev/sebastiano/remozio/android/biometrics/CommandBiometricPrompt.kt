package dev.sebastiano.remozio.android.biometrics

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import androidx.activity.ComponentActivity
import androidx.annotation.MainThread
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import dev.sebastiano.remozio.android.R
import dev.remozio.protocol.ApprovalMessage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface CommandBiometricResult {
    data class Signed(val message: ApprovalMessage) : CommandBiometricResult
    data object Cancelled : CommandBiometricResult
    data object Unavailable : CommandBiometricResult
}

/** Owns the supplied identity. Close on request replacement or enrollment change, including Compose disposal. */
@MainThread
class CommandBiometricPrompt(
    private val activity: ComponentActivity,
    private val identity: AndroidCommandBiometrics,
) : DefaultLifecycleObserver, AutoCloseable {
    private var closed = false
    private var token: Any? = null
    private var operation: CommandBiometricOperation? = null
    private var signal: CancellationSignal? = null
    private var monitor: Job? = null
    private var callback: ((CommandBiometricResult) -> Unit)? = null

    init { activity.lifecycle.addObserver(this) }

    /** Invoke from the execute control beside this identity's authenticated command capture. */
    fun authenticate(onResult: (CommandBiometricResult) -> Unit) {
        if (closed || token != null || !activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
            onResult(CommandBiometricResult.Unavailable)
            return
        }
        val attempt = try { identity.beginAttempt().also { token = it } }
            catch (_: Exception) { onResult(CommandBiometricResult.Unavailable); return }
        callback = onResult
        activity.lifecycleScope.launch {
            val prepared = try { withContext(Dispatchers.IO) { identity.prepare(attempt) } }
                catch (cancelled: CancellationException) { finish(attempt, CommandBiometricResult.Cancelled); throw cancelled }
                catch (_: Exception) { finish(attempt, CommandBiometricResult.Unavailable); return@launch }
            if (token !== attempt) { prepared.close(); return@launch }
            operation = prepared
            try {
                val cancellation = CancellationSignal().also { signal = it }
                val prompt = BiometricPrompt.Builder(activity)
                    .setTitle(activity.getString(R.string.command_biometric_title))
                    .setSubtitle(activity.getString(R.string.command_biometric_subtitle))
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButton(activity.getString(R.string.command_biometric_cancel), activity.mainExecutor) { _, _ ->
                        finish(attempt, CommandBiometricResult.Cancelled)
                    }.build()
                prompt.authenticate(BiometricPrompt.CryptoObject(prepared.signature), cancellation, activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (token !== attempt) return
                            val outcome = try {
                                check(activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))
                                check(result.authenticationType == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC)
                                CommandBiometricResult.Signed(prepared.complete(checkNotNull(result.cryptoObject?.signature)))
                            } catch (_: Exception) { CommandBiometricResult.Unavailable }
                            finish(attempt, outcome)
                        }
                        override fun onAuthenticationError(code: Int, message: CharSequence) {
                            finish(attempt, if (code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED ||
                                code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED) CommandBiometricResult.Cancelled
                                else CommandBiometricResult.Unavailable)
                        }
                    })
                monitor = activity.lifecycleScope.launch {
                    while (token === attempt) {
                        if (!identity.available()) { finish(attempt, CommandBiometricResult.Unavailable); break }
                        delay(250)
                    }
                }
            } catch (_: Exception) { finish(attempt, CommandBiometricResult.Unavailable) }
        }
    }

    private fun finish(attempt: Any, result: CommandBiometricResult) {
        if (token !== attempt) return
        token = null
        val notify = callback
        callback = null
        monitor?.cancel(); monitor = null
        signal?.cancel(); signal = null
        operation?.close(); operation = null
        identity.cancelAttempt(attempt)
        notify?.invoke(result)
    }

    fun cancel() { token?.let { finish(it, CommandBiometricResult.Cancelled) } }
    override fun onStop(owner: LifecycleOwner) { cancel() }
    override fun onDestroy(owner: LifecycleOwner) { close() }
    override fun close() {
        if (closed) return
        closed = true
        cancel()
        identity.close()
        activity.lifecycle.removeObserver(this)
    }
}
