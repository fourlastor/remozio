package dev.sebastiano.remozio.android.audit

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.phone.audit.AuditLocalSyncTime
import dev.remozio.protocol.CborValue
import org.junit.Test
import kotlin.test.*

class AuditSyncAgeTest {
    @Test fun elapsedAgesRequireTheSameNonRegressingClockAndARealObservation() {
        assertEquals(3500uL, auditSyncAgeMillis(ElapsedInstant(1, 5000u), ElapsedInstant(1, 1500u)))
        assertEquals(0uL, auditSyncAgeMillis(ElapsedInstant(1, 1500u), ElapsedInstant(1, 1500u)))
        assertNull(auditSyncAgeMillis(ElapsedInstant(2, 5000u), ElapsedInstant(1, 1500u)))
        assertNull(auditSyncAgeMillis(ElapsedInstant(1, 1000u), ElapsedInstant(1, 1500u)))
        assertNull(auditSyncAgeMillis(null, ElapsedInstant(1, 1500u)))
        assertNull(auditSyncAgeMillis(ElapsedInstant(1, 5000u), null))
        assertEquals(ULong.MAX_VALUE, auditSyncAgeMillis(ElapsedInstant(1, ULong.MAX_VALUE), ElapsedInstant(1, 0u)))
    }

    @Test fun savedDatesNeverBecomeElapsedFreshnessAndCannotOverrideALiveComparableObservation() {
        val saved = AuditLocalSyncTime(1_790_000_000_000L, CborValue.Bytes(ByteArray(32) { 7 }))
        assertEquals(AuditSyncTimestamp.ElapsedAge(4000u),
            auditSyncTimestamp(ElapsedInstant(1, 5000u), ElapsedInstant(1, 1000u), saved))
        assertEquals(AuditSyncTimestamp.PhoneTime(saved), auditSyncTimestamp(null, null, saved))
        assertEquals(AuditSyncTimestamp.PhoneTime(saved),
            auditSyncTimestamp(ElapsedInstant(2, 5000u), ElapsedInstant(1, 1000u), saved))
        assertEquals(AuditSyncTimestamp.PhoneTime(saved),
            auditSyncTimestamp(ElapsedInstant(1, 500u), ElapsedInstant(1, 1000u), saved))
        assertEquals(AuditSyncTimestamp.Unknown, auditSyncTimestamp(null, null, null))
        assertEquals(AuditSyncTimestamp.Unknown,
            auditSyncTimestamp(ElapsedInstant(2, 5000u), ElapsedInstant(1, 1000u), null))
    }

}
