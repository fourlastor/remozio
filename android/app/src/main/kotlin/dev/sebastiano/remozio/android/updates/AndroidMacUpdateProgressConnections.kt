package dev.sebastiano.remozio.android.updates

import android.content.Context
import dev.sebastiano.remozio.android.enrollment.AndroidEnrollmentStore
import kotlinx.coroutines.sync.Mutex

/** Creating the registry opens no transport and loads no identity. */
internal fun androidMacUpdateProgressConnections(
    context: Context,
    enrollmentAccess: Mutex,
    freshnessMillis: () -> Long,
    timeoutMillis: () -> Long,
): StoredMacUpdateProgressConnections {
    val app = context.applicationContext
    return StoredMacUpdateProgressConnections(
        { AndroidEnrollmentStore.openExisting(app, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
        { record, current ->
            MacUpdateProgressConnection(record,
                open = { parent, active -> androidMacUpdateProgressWire(app, parent, active, timeoutMillis(), current) },
                currentEnrollment = current, freshnessMillis = freshnessMillis, timeoutMillis = timeoutMillis)
        }, enrollmentAccess,
    )
}
