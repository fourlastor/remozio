package dev.sebastiano.remozio.android.routing

import android.content.Context
import android.annotation.SuppressLint
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

internal data class RoutingWorkPolicy(val refreshSeconds: Int = 10, val freshnessSeconds: Int = 30, val operationSeconds: Int = 30) {
    init { require(refreshSeconds in 1..3600 && freshnessSeconds in 1..3600 && operationSeconds in 1..60) }
}

/** Settings changes apply to the next sample or operation. They never replay an Away choice. */
internal class RoutingWorkSettings(context: Context) {
    private val preferences = context.getSharedPreferences("routing-work-policy-v1", Context.MODE_PRIVATE)
    private val changes = MutableStateFlow(read())
    val state = changes.asStateFlow()
    @Synchronized fun read(): RoutingWorkPolicy = try { RoutingWorkPolicy(
        preferences.getInt("refresh", 10), preferences.getInt("freshness", 30), preferences.getInt("operation", 30),
    ) } catch (_: Exception) { RoutingWorkPolicy() }
    // Commit returns the durable save result. The KTX helper discards that result.
    @SuppressLint("ApplySharedPref", "UseKtx")
    @Synchronized fun save(value: RoutingWorkPolicy): Boolean {
        val saved = try { preferences.edit().putInt("refresh", value.refreshSeconds).putInt("freshness", value.freshnessSeconds)
            .putInt("operation", value.operationSeconds).commit() } catch (_: Exception) { false }
        if (saved) changes.value = value
        return saved
    }
}
