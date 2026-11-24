package dev.sebastiano.remozio.android.enrollment

import android.os.SystemClock
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import dev.sebastiano.remozio.android.RemozioApplication
import dev.sebastiano.remozio.android.biometrics.AndroidPairingBiometrics
import dev.sebastiano.remozio.android.biometrics.PairingBiometricResult
import dev.remozio.protocol.PairingInvitationV2
import dev.remozio.protocol.PairingTranscript
import dev.remozio.protocol.RePairInvitation
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

internal enum class RePairAvailability { ELIGIBLE, PENDING, UNAVAILABLE }
internal enum class PairingPhase { CLOSED, INPUT, CONNECTING, COMPARING, PREPARING, BIOMETRIC, SUBMITTING, COMPLETE, RECOVERY_PENDING, FAILED, EXPIRED, CLOSING }
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
    suspend fun inspectRePair(input: String): RePairAvailability =
        inspectRePair { RePairInvitation.importText(input.trim()) }

    suspend fun inspectRePairV2(input: PairingInvitationV2): RePairAvailability =
        inspectRePair { RePairInvitation(input.invitation, checkNotNull(input.replacement)) }

    private suspend fun inspectRePair(invitation: () -> RePairInvitation): RePairAvailability {
        return try {
            app.pairing.inspectRePair(invitation())
            RePairAvailability.ELIGIBLE
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: RePairAlreadyPending) {
            RePairAvailability.PENDING
        } catch (_: Exception) {
            RePairAvailability.UNAVAILABLE
        }
    }

    fun connect(text: String): Boolean {
        val rePairSuffix = if (text.trim().startsWith("remozio-repair:")) runCatching {
            RePairInvitation.importText(text.trim()).predecessor.phoneID.copyBytes().suffix()
        }.getOrDefault("") else null
        return connect(rePairSuffix) { it.connect(text) }
    }

    fun connectV2(invitation: PairingInvitationV2) =
        connect(invitation.replacement?.phoneID?.copyBytes()?.suffix()) { it.connectV2(invitation) }

    private fun ByteArray.suffix() = takeLast(4).joinToString("") { "%02X".format(it.toInt() and 255) }

    private fun connect(rePairSuffix: String?, open: suspend (AndroidPairingAttempt) -> PairingTranscript): Boolean {
        if (mutable.value.phase != PairingPhase.INPUT || operation?.isActive == true) return false
        val owner = AndroidPairingAttempt(app, scope, app.pairing)
        attempt = owner
        val suffix = rePairSuffix ?: owner.phoneSuffix
        mutable.value = PairingScreenState(PairingPhase.CONNECTING, suffix)
        operation = scope.launch {
            try {
                val transcript = open(owner)
                if (attempt === owner) {
                    val now = System.currentTimeMillis().coerceAtLeast(0).toULong()
                    val remaining = if (now >= transcript.expiresAtUnixMillis) 0uL else
                        minOf(transcript.expiresAtUnixMillis - now, transcript.expiresAtUnixMillis - transcript.issuedAtUnixMillis)
                    mutable.value = mutable.value.copy(phase = PairingPhase.COMPARING, transcript = transcript, comparisonCode = transcript.verificationCode(),
                        expiresElapsedMillis = SystemClock.elapsedRealtime() + remaining.toLong())
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) {
                val result = app.retirePairing(owner).await()
                if (attempt === owner) {
                    if (result.isSuccess) attempt = null
                    mutable.value = mutable.value.copy(phase = if (failure is RePairAlreadyPending)
                        PairingPhase.RECOVERY_PENDING else PairingPhase.FAILED, mayHaveSavedSetup = result.isFailure)
                }
            }
        }
        return true
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
            if (result?.isFailure == true) attempt = owner
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
