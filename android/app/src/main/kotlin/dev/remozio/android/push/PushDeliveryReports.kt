package dev.remozio.android.push

import android.content.Context
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

internal enum class PushDeliveryStatus { QUEUED, ALERT_REQUESTED, PERMISSION_BLOCKED, CHANNEL_BLOCKED, UNAVAILABLE, CAPACITY_LIMIT, IGNORED }
internal class PushDeliveryReport(val generation: UUID, val status: PushDeliveryStatus) {
    override fun toString() = "PushDeliveryReport(redacted)"
}

/** Coarse local diagnostics only. The record contains no token, wake, enrollment, endpoint or request data. */
internal class PushDeliveryReports(context: Context) {
    private val preferences = context.getSharedPreferences("push-local-health-v1", Context.MODE_PRIVATE)
    private val changes = MutableStateFlow(read())
    val state = changes.asStateFlow()
    @Synchronized fun record(generation: UUID, status: PushDeliveryStatus) {
        val saved = preferences.edit().putString("generation", generation.toString()).putString("status", status.name).commit()
        changes.value = PushDeliveryReport(generation, if (saved) status else PushDeliveryStatus.UNAVAILABLE)
    }
    private fun read(): PushDeliveryReport? = try {
        val generation = preferences.getString("generation", null)
        val status = preferences.getString("status", null)
        if (generation == null || status == null) null else PushDeliveryReport(UUID.fromString(generation), PushDeliveryStatus.valueOf(status))
    } catch (_: Exception) { null }
}
