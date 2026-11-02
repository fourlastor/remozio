package dev.sebastiano.remozio.android.push

import org.junit.Test
import kotlin.test.*

class NotificationSetupTest {
    @Test fun permissionAndAppDenialCannotBeHiddenByAnAllowedChannel() {
        for (importance in listOf(null, 0, 1, 3, 4, 5)) {
            assertEquals(NotificationAccess.PERMISSION_REQUIRED, notificationAccess(false, true, importance))
            assertEquals(NotificationAccess.PERMISSION_REQUIRED, notificationAccess(false, false, importance))
            assertEquals(NotificationAccess.APP_DISABLED, notificationAccess(true, false, importance))
            assertFalse(notificationAccess(false, true, importance).canTest)
            assertFalse(notificationAccess(true, false, importance).canTest)
        }
    }

    @Test fun anAbsentChannelIsDifferentFromAUserDisabledChannel() {
        assertEquals(NotificationAccess.CHANNEL_MISSING, notificationAccess(true, true, null))
        assertEquals(NotificationAccess.CHANNEL_DISABLED, notificationAccess(true, true, 0))
        assertFalse(notificationAccess(true, true, null).canTest)
        assertFalse(notificationAccess(true, true, 0).canTest)
    }

    @Test fun lowerImportanceStillPermitsAnExplicitLocalTest() {
        for (importance in 1..3) {
            assertEquals(NotificationAccess.QUIET, notificationAccess(true, true, importance))
            assertTrue(notificationAccess(true, true, importance).canTest)
        }
        for (importance in 4..5) {
            assertEquals(NotificationAccess.ALLOWED, notificationAccess(true, true, importance))
            assertTrue(notificationAccess(true, true, importance).canTest)
        }
    }

    @Test fun unavailableAndUnexpectedImportanceNeverClaimPostingIsAllowed() {
        for (importance in listOf(Int.MIN_VALUE, -1000, -1, 6, Int.MAX_VALUE)) {
            assertEquals(NotificationAccess.UNAVAILABLE, notificationAccess(true, true, importance))
            assertFalse(notificationAccess(true, true, importance).canTest)
        }
        assertFalse(NotificationAccess.UNAVAILABLE.canTest)
    }
}
