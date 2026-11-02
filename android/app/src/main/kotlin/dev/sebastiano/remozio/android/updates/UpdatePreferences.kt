package dev.sebastiano.remozio.android.updates

import android.annotation.SuppressLint
import android.content.Context

internal data class UpdatePreferences(
    val automatic: Boolean = true,
    val intervalHours: Int = 24,
    val prereleases: Boolean = false,
    val overridden: Boolean = false,
    val lastAttemptMillis: Long = 0,
) {
    init { require(intervalHours in 1..168 && lastAttemptMillis >= 0) }
    fun due(now: Long) = automatic && (lastAttemptMillis == 0L || now < lastAttemptMillis ||
        now - lastAttemptMillis >= intervalHours * 3_600_000L)
}

internal interface UpdatePreferencesStore {
    fun load(): UpdatePreferences
    fun save(value: UpdatePreferences)
}

internal class AndroidUpdatePreferences(context: Context) : UpdatePreferencesStore {
    private val preferences = context.applicationContext.getSharedPreferences("update-checks-v1", Context.MODE_PRIVATE)
    override fun load(): UpdatePreferences {
        check(preferences.getInt("schema", 1) == 1)
        return UpdatePreferences(preferences.getBoolean("automatic", true), preferences.getInt("hours", 24),
            preferences.getBoolean("prereleases", false), preferences.getBoolean("overridden", false),
            preferences.getLong("last-attempt", 0))
    }
    @SuppressLint("UseKtx") // The KTX helper discards the commit result.
    override fun save(value: UpdatePreferences) {
        check(preferences.edit().putInt("schema", 1).putBoolean("automatic", value.automatic)
            .putInt("hours", value.intervalHours).putBoolean("prereleases", value.prereleases)
            .putBoolean("overridden", value.overridden).putLong("last-attempt", value.lastAttemptMillis).commit())
    }
}
