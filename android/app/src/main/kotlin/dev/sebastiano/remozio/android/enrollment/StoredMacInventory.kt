package dev.sebastiano.remozio.android.enrollment

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.EnrollmentSnapshot
import dev.remozio.protocol.CborValue
import java.util.Collections
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Display metadata only. A stored phase establishes neither current peer trust nor presence. */
internal class StoredMac(val recordID: CborValue.Bytes, val label: String, val setupIncomplete: Boolean) {
    override fun toString() = "StoredMac(redacted)"
}

internal sealed interface MacInventoryState {
    data object Loading : MacInventoryState
    data object Unavailable : MacInventoryState
    class Ready(macs: List<StoredMac>) : MacInventoryState {
        val macs: List<StoredMac> = Collections.unmodifiableList(macs.toList())
        override fun toString() = "MacInventoryState.Ready(redacted)"
    }
}

internal fun storedMacs(snapshot: EnrollmentSnapshot): MacInventoryState.Ready = MacInventoryState.Ready(
    snapshot.entries.filter { it.phase != EnrollmentPhase.REMOVED }.map {
        StoredMac(it.enrollment.recordID, it.enrollment.label, it.phase == EnrollmentPhase.PREPARED)
    },
)

/** Serializes readers across activities and closes the archive before exposing metadata to Compose. */
internal class StoredMacReader(
    private val open: () -> EncryptedEnrollmentStore?,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val enrollmentAccess: Mutex = Mutex(),
) {
    private val mutex = Mutex()
    suspend fun read(): MacInventoryState = mutex.withLock {
        try {
            withContext(dispatcher) {
                enrollmentAccess.withLock {
                    open()?.use { storedMacs(it.snapshot()) } ?: MacInventoryState.Ready(emptyList())
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            MacInventoryState.Unavailable
        }
    }
}
