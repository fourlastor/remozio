package dev.remozio.android.push

import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

internal interface PushConfigurationStorage {
    fun read(): StoredPushConfiguration?
    fun replace(configuration: StoredPushConfiguration)
}

internal interface PushClientDriver {
    fun start(configuration: FCMClientConfiguration, token: (String) -> Unit, failed: () -> Unit)
    fun stop()
}

internal enum class PushClientStatus { UNCONFIGURED, DISABLED, INITIALIZING, CLIENT_READY, REGISTRATION_FAILED, RESTART_REQUIRED, UNAVAILABLE }
internal enum class PushConfigurationResult { IMPORTED, UNCHANGED, RESTART_REQUIRED, INVALID, FAILED }

/** The token is a private delivery address. It grants no enrollment, fetch or decision authority. */
internal class PushTokenCandidate(val generation: UUID, val revision: UUID, val projectID: String, val token: String) {
    override fun toString() = "PushTokenCandidate(redacted)"
}

/** Owns one default Firebase app per process. A changed project takes effect on the next app process. */
internal class PushClientOwner(
    private val expectedPackage: String,
    private val storage: PushConfigurationStorage,
    private val driver: PushClientDriver,
    private val newGeneration: () -> UUID = UUID::randomUUID,
) {
    private val mutableStatus = MutableStateFlow(PushClientStatus.UNCONFIGURED)
    val status = mutableStatus.asStateFlow()
    private val mutableGeneration = MutableStateFlow<UUID?>(null)
    val generationState = mutableGeneration.asStateFlow()
    private var desired: StoredPushConfiguration? = null
    private var started: StoredPushConfiguration? = null
    private var candidate: PushTokenCandidate? = null
    private var restored = false
    private var attempt = UUID.randomUUID()

    @Synchronized fun restore() {
        if (restored) return
        restored = true
        try { desired = storage.read(); apply() }
        catch (_: Exception) { retire(); publish(PushClientStatus.UNAVAILABLE) }
    }

    @Synchronized fun import(bytes: ByteArray): PushConfigurationResult {
        val client = try { FCMClientConfiguration.import(bytes, expectedPackage) }
            catch (_: Exception) { return PushConfigurationResult.INVALID }
        if (!restored) restore()
        if (desired?.client?.sameAs(client) == true) return PushConfigurationResult.UNCHANGED
        return try {
            val next = StoredPushConfiguration(newGeneration(), client, true)
            storage.replace(next)
            desired = next; candidate = null
            apply()
            if (mutableStatus.value == PushClientStatus.RESTART_REQUIRED) PushConfigurationResult.RESTART_REQUIRED
                else PushConfigurationResult.IMPORTED
        } catch (_: Exception) { retire(); desired = null; publish(PushClientStatus.UNAVAILABLE); PushConfigurationResult.FAILED }
    }

    @Synchronized fun setEnabled(enabled: Boolean): Boolean {
        if (!restored) restore()
        val current = desired ?: return false
        if (current.enabled == enabled) return true
        return try {
            val next = StoredPushConfiguration(newGeneration(), current.client, enabled)
            storage.replace(next)
            desired = next; candidate = null
            apply(); true
        } catch (_: Exception) { retire(); desired = null; publish(PushClientStatus.UNAVAILABLE); false }
    }

    @Synchronized fun retry() {
        if (!restored) restore()
        if (desired?.enabled == true && mutableStatus.value != PushClientStatus.RESTART_REQUIRED) {
            candidate = null; publish(PushClientStatus.REGISTRATION_FAILED); apply()
        }
    }
    @Synchronized fun enabled(): Boolean = desired?.enabled == true
    @Synchronized fun configured(): Boolean = desired != null
    @Synchronized fun acceptsSender(sender: String?): Boolean = current()?.client?.senderID?.let { it == sender } == true
    @Synchronized fun generation(): UUID? = current()?.generation
    @Synchronized fun tokenCandidate(): PushTokenCandidate? = if (current() != null) candidate else null

    /** Called only by this process's Firebase service, never by an exported application intent. */
    @Synchronized fun tokenChanged() { if (current() != null) retry() }

    /** Serializes local notification publication with disabling or replacing this provider configuration. */
    @Synchronized fun <T> withCurrent(generation: UUID, body: () -> T): T? {
        if (current()?.generation != generation) return null
        return body()
    }

    @Synchronized fun <T> withCurrentOrDisabled(generation: UUID?, body: () -> T): T? {
        if (current()?.generation != generation) return null
        return body()
    }

    private fun current(): StoredPushConfiguration? {
        val selected = desired ?: return null
        return selected.takeIf { it.enabled && started?.generation == it.generation && mutableStatus.value != PushClientStatus.UNAVAILABLE }
    }
    private fun publish(status: PushClientStatus) {
        mutableStatus.value = status
        mutableGeneration.value = current()?.generation
    }
    private fun retire() {
        candidate = null
        try { driver.stop() } catch (_: Exception) { }
    }
    private fun apply() {
        val selected = desired
        if (selected == null) { publish(PushClientStatus.UNCONFIGURED); return }
        if (!selected.enabled) { retire(); publish(PushClientStatus.DISABLED); return }
        val previous = started
        if (previous != null && !previous.client.sameAs(selected.client)) {
            retire(); publish(PushClientStatus.RESTART_REQUIRED); return
        }
        if (previous?.generation == selected.generation && mutableStatus.value in setOf(PushClientStatus.CLIENT_READY, PushClientStatus.INITIALIZING)) return
        started = selected
        publish(PushClientStatus.INITIALIZING)
        val request = UUID.randomUUID(); attempt = request
        try {
            driver.start(selected.client, { token -> synchronized(this) {
                if (attempt == request) acceptToken(selected.generation, token)
            } }, {
                synchronized(this) {
                    if (attempt == request && current()?.generation == selected.generation) {
                        candidate = null; publish(PushClientStatus.REGISTRATION_FAILED)
                    }
                }
            })
        } catch (_: Exception) { retire(); publish(PushClientStatus.UNAVAILABLE) }
    }
    private fun acceptToken(generation: UUID, token: String) {
        val selected = current() ?: return
        if (selected.generation != generation) return
        if (token.length !in 1..4096 || token.any { it.code !in 33..126 }) {
            candidate = null; publish(PushClientStatus.REGISTRATION_FAILED); return
        }
        if (candidate?.token != token) candidate = PushTokenCandidate(generation, newGeneration(), selected.client.projectID, token)
        publish(PushClientStatus.CLIENT_READY)
    }
}
