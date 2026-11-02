package dev.remozio.android.audit

import android.content.Context
import kotlinx.coroutines.sync.Mutex
import dev.remozio.android.enrollment.AndroidEnrollmentStore

/** Decoder limits only. This reader never selects retention or prunes an archive. */
internal fun androidStoredAuditReader(context: Context, enrollmentAccess: Mutex,
                                     readSnapshot: AuditSnapshotRead): StoredAuditReader {
    val app = context.applicationContext
    val protocol = auditPageLimits()
    return StoredAuditReader(
        enrollmentAccess = enrollmentAccess,
        readSnapshot = readSnapshot,
        openEnrollments = { AndroidEnrollmentStore.openExisting(app, 1024, 16_777_216) },
        openCache = { binding, maximumBytes ->
            AndroidAuditCache.openExisting(app, binding, protocol,
                auditEvidenceLimits(maximumBytes), auditArchiveLimits(maximumBytes))
        },
    )
}
