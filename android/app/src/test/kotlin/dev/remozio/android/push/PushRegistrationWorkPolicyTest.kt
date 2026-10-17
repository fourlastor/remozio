package dev.remozio.android.push

import dev.remozio.protocol.CborValue
import org.junit.Test
import kotlin.test.*

class PushRegistrationWorkPolicyTest {
    private fun id(n: Int) = CborValue.Bytes(ByteArray(16) { n.toByte() })
    @Test fun boundedQueuesAdvancePastTheLastAdmittedMacAndWrapWithoutDroppingAnyRecord() {
        val records = listOf(id(3), id(1), id(2), id(1))
        assertEquals(listOf(id(1), id(2), id(3)), registrationWorkOrder(records, null))
        assertEquals(listOf(id(2), id(3), id(1)), registrationWorkOrder(records, id(1)))
        assertEquals(listOf(id(3), id(1), id(2)), registrationWorkOrder(records, id(2)))
        assertEquals(listOf(id(1), id(2), id(3)), registrationWorkOrder(records, id(3)))
        assertEquals(listOf(id(2), id(3)), registrationWorkOrder(listOf(id(3), id(2)), id(1)))
        assertTrue(registrationWorkOrder(emptyList(), id(1)).isEmpty())
    }
    @Test fun workIdentifiersRequireTheExactLowercaseOpaqueWidth() {
        assertEquals(id(12), registrationIdentifier(id(12).hex(), 16))
        assertNull(registrationIdentifier(null, 16))
        assertNull(registrationIdentifier("00", 16))
        assertNull(registrationIdentifier("ZZ".repeat(16), 16))
        assertNull(registrationIdentifier("AB".repeat(16), 16))
        assertNull(registrationIdentifier("00".repeat(32), 16))
    }
    @Test fun settingsAcceptThePlatformMinimumAndBoundedExtremes() {
        PushRegistrationWorkPolicy(1, 1, 1, 10, 1, 15)
        PushRegistrationWorkPolicy(4096, 64, 20, 3600, 60, 1440)
        assertFailsWith<IllegalArgumentException> { PushRegistrationWorkPolicy(queueLimit = 0) }
        assertFailsWith<IllegalArgumentException> { PushRegistrationWorkPolicy(maximumConcurrent = 65) }
        assertFailsWith<IllegalArgumentException> { PushRegistrationWorkPolicy(maximumAttempts = 0) }
        assertFailsWith<IllegalArgumentException> { PushRegistrationWorkPolicy(backoffSeconds = 9) }
        assertFailsWith<IllegalArgumentException> { PushRegistrationWorkPolicy(operationSeconds = 61) }
        assertFailsWith<IllegalArgumentException> { PushRegistrationWorkPolicy(reconcileMinutes = 14) }
    }
    @Test fun staleCollectorsCannotReplaceOrCancelTheNewTokenWorkSelection() {
        val f = PushClientFixture(); f.enable(); f.driver.attempts.single().token("first-token")
        val first = assertNotNull(f.owner.tokenCandidate()); var changes = 0
        assertNotNull(f.owner.withCurrentTokenOrDisabled(first.generation, first.revision) { changes++; true })
        f.driver.attempts.single().token("replacement-token")
        val next = assertNotNull(f.owner.tokenCandidate())
        assertNull(f.owner.withCurrentTokenOrDisabled(first.generation, first.revision) { changes++; true })
        assertNotNull(f.owner.withCurrentTokenOrDisabled(next.generation, next.revision) { changes++; true })
        assertTrue(f.owner.setEnabled(false))
        assertNull(f.owner.withCurrentTokenOrDisabled(next.generation, next.revision) { changes++; true })
        assertNotNull(f.owner.withCurrentTokenOrDisabled(null, null) { changes++; true })
        assertEquals(3, changes)
    }

}
