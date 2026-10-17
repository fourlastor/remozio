package dev.remozio.android.push

import android.content.Context
import android.annotation.SuppressLint
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

internal data class PushRegistrationWorkPolicy(
    val queueLimit: Int = 256,
    val maximumConcurrent: Int = 4,
    val maximumAttempts: Int = 5,
    val backoffSeconds: Int = 10,
    val operationSeconds: Int = 30,
    val reconcileMinutes: Int = 15,
) {
    init {
        require(queueLimit in 1..4096 && maximumConcurrent in 1..64)
        require(maximumAttempts in 1..20 && backoffSeconds in 10..3600)
        require(operationSeconds in 1..60 && reconcileMinutes in 15..1440)
    }
}
internal class PushRegistrationWorkSettings(context: Context) {
    private val preferences = context.getSharedPreferences("push-registration-policy-v1", Context.MODE_PRIVATE)
    private val changes = MutableStateFlow(read())
    val state = changes.asStateFlow()
    @Synchronized fun read(): PushRegistrationWorkPolicy = try { PushRegistrationWorkPolicy(
        preferences.getInt("queue", 256), preferences.getInt("parallel", 4),
        preferences.getInt("attempts", 5), preferences.getInt("backoff", 10),
        preferences.getInt("operation", 30), preferences.getInt("reconcile", 15),
    ) } catch (_: Exception) { PushRegistrationWorkPolicy() }
    @SuppressLint("ApplySharedPref", "UseKtx")
    @Synchronized fun save(value: PushRegistrationWorkPolicy): Boolean {
        val saved = try { preferences.edit().putInt("queue", value.queueLimit)
            .putInt("parallel", value.maximumConcurrent).putInt("attempts", value.maximumAttempts)
            .putInt("backoff", value.backoffSeconds).putInt("operation", value.operationSeconds)
            .putInt("reconcile", value.reconcileMinutes).commit() } catch (_: Exception) { false }
        if (saved) changes.value = value
        return saved
    }
}
