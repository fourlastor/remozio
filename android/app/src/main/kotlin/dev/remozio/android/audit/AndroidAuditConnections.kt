package dev.remozio.android.audit

import android.content.Context
import android.os.SystemClock
import dev.remozio.android.enrollment.AndroidEnrollmentStore
import dev.remozio.phone.audit.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.CborLimits
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.sync.Mutex

internal fun auditPageLimits() = AuditPageLimits(
    batch = CborLimits(1_048_576, 8, 131_072), record = CborLimits(4096, 4, 64),
    signing = CborLimits(1_050_624, 8, 32), maximumRecords = 2048,
    history = CborLimits(16_384, 8, 256), descriptor = CborLimits(4096, 4, 64),
)
internal fun auditEvidenceLimits(maximumBytes: Int) = AuditEvidenceLimits(
    maximumProofs = 4096, maximumBytes = maximumBytes.toLong(), maximumRecords = 50_000, maximumEpochs = 4096,
)
internal fun auditArchiveLimits(maximumBytes: Int) = CborLimits(maximumBytes, 8, 65_536)

/** The factory acquires one cache. It starts no network work until the owner receives an explicit sync request. */
internal fun androidAuditConnections(context: Context, parent: CoroutineScope, enrollmentAccess: Mutex,
                                    policy: () -> AuditWorkPolicy): StoredAuditConnections {
    val app = context.applicationContext
    return StoredAuditConnections(parent,
        openEnrollments = { AndroidEnrollmentStore.openExisting(app, 1024, 16_777_216) },
        create = { record, retained, current ->
            val enrollment = record.enrollment
            val binding = AuditCacheBinding(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(), enrollment.authorityPublicKey.copyBytes())
            val cache = AndroidAuditCache.open(app, binding, auditPageLimits(), auditEvidenceLimits(16_777_216),
                auditArchiveLimits(16_777_216), retained)
            try {
                val session = AuditSyncSession(cache, 32, 30_000u) {
                    ElapsedInstant(1, SystemClock.elapsedRealtime().toULong())
                }
                PhoneAuditSyncConnection(record, session,
                    { owner, active, limits -> androidAuditWire(app, owner, active, limits.timeoutMillis) }, current,
                    { policy().let { AuditRoundLimits(it.responseBudget, it.operationSeconds * 1000L) } })
            } catch (failure: Throwable) { cache.close(); throw failure }
        }, enrollmentAccess = enrollmentAccess)
}
