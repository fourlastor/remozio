package dev.remozio.android.enrollment

import android.os.SystemClock
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import dev.remozio.android.RemozioApplication
import dev.remozio.android.biometrics.AndroidPairingBiometrics
import dev.remozio.android.biometrics.PairingBiometricResult
import dev.remozio.protocol.PairingTranscript
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

internal enum class PairingPhase { CLOSED, INPUT, CONNECTING, COMPARING, PREPARING, BIOMETRIC, SUBMITTING, COMPLETE, FAILED, EXPIRED, CLOSING }
internal data class PairingScreenState(
    val phase: PairingPhase = PairingPhase.CLOSED,
    val phoneSuffix: String = "",
    val transcript: PairingTranscript? = null,
    val comparisonCode: String? = null,
    val expiresElapsedMillis: Long? = null,
    val signer: AndroidPairingBiometrics? = null,
    val mayHaveSavedSetup: Boolean = false,
)

/** Retains one setup owner across rotation. Activity and biometric prompts are never retained here. */
internal class PairingViewModel(private val app: RemozioApplication) : ViewModel() {
    private val job = SupervisorJob()
    private val scope = CoroutineScope(job + Dispatchers.Main.immediate)
    private val mutable = MutableStateFlow(PairingScreenState())
    val state = mutable.asStateFlow()
    private var attempt: AndroidPairingAttempt? = null
    private var operation: Job? = null
    private var foreground = false
    private var foregroundRevision = 0L

    fun open() {
        if (mutable.value.phase == PairingPhase.CLOSED) mutable.value = PairingScreenState(PairingPhase.INPUT)
    }
    fun foreground(value: Boolean) {
        foreground = value
        if (!value) foregroundRevision++
    }
    fun connect(text: String) {
        if (mutable.value.phase != PairingPhase.INPUT || operation?.isActive == true) return
        val owner = AndroidPairingAttempt(app, scope, app.pairing)
        attempt = owner
        mutable.value = PairingScreenState(PairingPhase.CONNECTING, owner.phoneSuffix)
        operation = scope.launch {
            try {
                val transcript = owner.connect(text)
                if (attempt === owner) {
                    val now = System.currentTimeMillis().coerceAtLeast(0).toULong()
                    val remaining = if (now >= transcript.expiresAtUnixMillis) 0uL else
                        minOf(transcript.expiresAtUnixMillis - now, transcript.expiresAtUnixMillis - transcript.issuedAtUnixMillis)
                    mutable.value = mutable.value.copy(phase = PairingPhase.COMPARING, transcript = transcript, comparisonCode = transcript.verificationCode(),
                        expiresElapsedMillis = SystemClock.elapsedRealtime() + remaining.toLong())
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { if (attempt === owner) mutable.value = mutable.value.copy(phase = PairingPhase.FAILED) }
        }
    }
    fun confirmComparison() {
        if (!foreground || mutable.value.phase != PairingPhase.COMPARING || operation?.isActive == true) return
        if (mutable.value.expiresElapsedMillis?.let { SystemClock.elapsedRealtime() >= it } == true) {
            expire()
            return
        }
        val owner = checkNotNull(attempt)
        val revision = foregroundRevision
        mutable.value = mutable.value.copy(phase = PairingPhase.PREPARING, mayHaveSavedSetup = true)
        operation = scope.launch {
            try {
                val signer = owner.confirmComparison()
                if (attempt !== owner || !foreground || foregroundRevision != revision) {
                    signer.close()
                    if (attempt === owner) mutable.value = mutable.value.copy(phase = PairingPhase.COMPARING, signer = null)
                } else mutable.value = mutable.value.copy(phase = PairingPhase.BIOMETRIC, signer = signer)
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { if (attempt === owner) mutable.value = mutable.value.copy(phase = PairingPhase.FAILED, signer = null) }
        }
    }
    fun biometricResult(signer: AndroidPairingBiometrics, result: PairingBiometricResult) {
        if (mutable.value.phase != PairingPhase.BIOMETRIC || mutable.value.signer !== signer) return
        signer.close()
        if (result !is PairingBiometricResult.Signed || !foreground) {
            mutable.value = mutable.value.copy(phase = PairingPhase.COMPARING, signer = null)
            return
        }
        val owner = checkNotNull(attempt)
        mutable.value = mutable.value.copy(phase = PairingPhase.SUBMITTING, signer = null)
        operation = scope.launch {
            try {
                owner.submit(result.proof)
                if (attempt === owner) mutable.value = mutable.value.copy(phase = PairingPhase.COMPLETE)
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { if (attempt === owner) mutable.value = mutable.value.copy(phase = PairingPhase.FAILED) }
        }
    }
    fun expire() {
        if (mutable.value.phase == PairingPhase.COMPARING) {
            mutable.value = mutable.value.copy(phase = PairingPhase.EXPIRED, signer = null)
            attempt?.close()
        }
    }
    fun close() {
        if (mutable.value.phase == PairingPhase.CLOSED || mutable.value.phase == PairingPhase.CLOSING) return
        val owner = attempt
        attempt = null
        mutable.value.signer?.close()
        mutable.value = mutable.value.copy(phase = PairingPhase.CLOSING, signer = null)
        operation?.cancel()
        val retiring = owner?.let(app::retirePairing)
        scope.launch {
            val result = retiring?.await()
            operation?.join()
            mutable.value = if (result?.isFailure == true) mutable.value.copy(phase = PairingPhase.FAILED)
                else PairingScreenState()
        }
    }
    override fun onCleared() {
        mutable.value.signer?.close()
        attempt?.let(app::retirePairing)
        attempt = null
        job.cancel()
    }
    class Factory(private val app: RemozioApplication) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass == PairingViewModel::class.java)
            @Suppress("UNCHECKED_CAST")
            return PairingViewModel(app) as T
        }
    }
}
