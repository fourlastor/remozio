package dev.remozio.android.push

import android.content.Context
import kotlinx.coroutines.flow.asStateFlow

internal data class WakeWorkPolicy(
    val ingressLimit: Int = 256,
    val fetchLimit: Int = 256,
    val maximumAttempts: Int = 5,
    val backoffSeconds: Int = 10,
    val snapshotSeconds: Int = 30,
    val reconcileMinutes: Int = 15,
) {
    init {
        require(ingressLimit in 1..4096 && fetchLimit in 1..4096)
        require(maximumAttempts in 1..20 && backoffSeconds in 10..3600)
        require(snapshotSeconds in 1..60 && reconcileMinutes in 15..1440)
    }
}
internal class WakeWorkSettings(context: Context) {
    private val preferences = context.getSharedPreferences("wake-work-policy-v1", Context.MODE_PRIVATE)
    private val changes = kotlinx.coroutines.flow.MutableStateFlow(read())
    val state = changes.asStateFlow()
    @Synchronized fun read(): WakeWorkPolicy = try { WakeWorkPolicy(
        preferences.getInt("ingress", 256), preferences.getInt("fetch", 256),
        preferences.getInt("attempts", 5), preferences.getInt("backoff", 10),
        preferences.getInt("snapshot", 30), preferences.getInt("reconcile", 15),
    ) } catch (_: Exception) { WakeWorkPolicy() }
    @Synchronized fun save(value: WakeWorkPolicy): Boolean {
        val saved = try { preferences.edit()
        .putInt("ingress", value.ingressLimit).putInt("fetch", value.fetchLimit)
        .putInt("attempts", value.maximumAttempts).putInt("backoff", value.backoffSeconds)
        .putInt("snapshot", value.snapshotSeconds).putInt("reconcile", value.reconcileMinutes).commit() } catch (_: Exception) { false }
        if (saved) changes.value = value
        return saved
    }
}
