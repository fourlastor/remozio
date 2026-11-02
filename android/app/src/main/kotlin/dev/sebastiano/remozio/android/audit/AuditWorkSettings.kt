package dev.sebastiano.remozio.android.audit

import android.content.Context
import android.content.SharedPreferences
import android.annotation.SuppressLint
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Bounds one explicit sync round. These are work limits, not permission to prune history. */
internal data class AuditWorkPolicy(val responseBudget: Int = 32, val operationSeconds: Int = 30) {
    init { require(responseBudget in 1..4096 && operationSeconds in 1..60) }
}

/** Each explicit round captures this policy. Saving alone never starts work or deletes retained evidence. */
internal class AuditWorkSettings(initial: AuditWorkPolicy, private val persist: (AuditWorkPolicy) -> Boolean) {
    constructor(context: Context) : this(context.getSharedPreferences("audit-work-policy-v1", Context.MODE_PRIVATE))
    private constructor(preferences: SharedPreferences) : this(load(preferences), { write(preferences, it) })
    private val changes = MutableStateFlow(initial)
    val state = changes.asStateFlow()
    @Synchronized fun read(): AuditWorkPolicy = changes.value
    @Synchronized fun save(value: AuditWorkPolicy): Boolean {
        val saved = try { persist(value) } catch (_: Exception) { false }
        if (saved) changes.value = value
        return saved
    }
    private companion object {
        fun load(preferences: SharedPreferences): AuditWorkPolicy = try { AuditWorkPolicy(
            preferences.getInt("responses", 32), preferences.getInt("operation", 30),
        ) } catch (_: Exception) { AuditWorkPolicy() }
        @SuppressLint("ApplySharedPref", "UseKtx")
        fun write(preferences: SharedPreferences, value: AuditWorkPolicy): Boolean = preferences.edit()
            .putInt("responses", value.responseBudget).putInt("operation", value.operationSeconds).commit()
    }
}
