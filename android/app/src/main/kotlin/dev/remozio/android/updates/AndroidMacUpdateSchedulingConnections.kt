package dev.remozio.android.updates

import android.content.Context
import android.os.SystemClock
import dev.remozio.android.decisions.AndroidDecisionIdentities
import dev.remozio.android.enrollment.AndroidEnrollmentStore
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge
import kotlinx.coroutines.sync.Mutex

/** Loading an owner opens no connection or decision key. A status read never loads decision custody. */
internal fun androidMacUpdateSchedulingConnections(
    context: Context,
    enrollmentAccess: Mutex,
    freshnessMillis: () -> Long,
    timeoutMillis: () -> Long,
): StoredMacUpdateSchedulingConnections {
    val app = context.applicationContext
    return StoredMacUpdateSchedulingConnections(
        { AndroidEnrollmentStore.openExisting(app, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
        { record, current ->
            MacUpdateSchedulingConnection(record,
                open = { parent, active -> androidMacUpdateSchedulingWire(app, parent, active, timeoutMillis(), current) },
                loadSigner = { active ->
                    val identity = AndroidDecisionIdentities.load(active)
                    object : UpdateSchedulingDecisionSigner {
                        override fun sign(challenge: PhoneUpdateSchedulingChallenge, current: StoredPhoneEnrollment) =
                            identity.signUpdateScheduling(challenge, current)
                        override fun close() = identity.close()
                    }
                }, currentEnrollment = current, elapsedRealtimeNanos = SystemClock::elapsedRealtimeNanos,
                freshnessMillis = freshnessMillis, timeoutMillis = timeoutMillis)
        }, enrollmentAccess,
    )
}
