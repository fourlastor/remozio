package dev.remozio.android.push

import dev.remozio.phone.push.WakeNotificationResult
import dev.remozio.phone.push.WakeReceipt
import dev.remozio.phone.push.WakeReception
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class FCMServiceIngressTest {
    @Test fun rejectedDeliveriesAreAcknowledgedWithoutSDKRendering() {
        for (action in listOf("com.google.android.c2dm.intent.RECEIVE", "com.google.firebase.messaging.RECEIVE_DIRECT_BOOT")) {
            for ((enabled, keys) in listOf(false to emptySet(), true to setOf("gcm.n.e"), true to setOf("gcm.notification.title"))) {
                var acknowledgements = 0; var deliveries = 0
                dispatchFCMIntent(action, enabled, keys, { acknowledgements++ }, { deliveries++ })
                assertEquals(1, acknowledgements); assertEquals(0, deliveries)
            }
        }
    }
    @Test fun acceptedDataAndNonDeliveryEventsStayOnSDKPath() {
        for ((action, enabled) in listOf("com.google.android.c2dm.intent.RECEIVE" to true,
                "com.google.firebase.messaging.NEW_TOKEN" to false, "unknown" to false, null to false)) {
            var acknowledgements = 0; var deliveries = 0
            dispatchFCMIntent(action, enabled, emptySet(), { acknowledgements++ }, { deliveries++ })
            assertEquals(0, acknowledgements); assertEquals(1, deliveries)
        }
    }
    @Test fun acknowledgementFailureCannotFallThroughToSDKRendering() {
        var deliveries = 0
        assertFailsWith<IllegalStateException> {
            dispatchFCMIntent("com.google.android.c2dm.intent.RECEIVE", false, emptySet(),
                { error("Unavailable acknowledgement") }, { deliveries++ })
        }
        assertEquals(0, deliveries)
    }
    @Test fun completedReceiptsAlwaysReplaceQueuedStatus() {
        for (reception in WakeReception.entries) {
            val expected = if (reception in setOf(WakeReception.DUPLICATE, WakeReception.UNKNOWN_ENROLLMENT,
                    WakeReception.TOKEN_CHALLENGE, WakeReception.MALFORMED)) PushDeliveryStatus.IGNORED else PushDeliveryStatus.UNAVAILABLE
            assertEquals(expected, wakeDeliveryStatus(WakeReceipt(reception)))
        }
        assertEquals(PushDeliveryStatus.UNAVAILABLE, wakeDeliveryStatus(null))
        for ((notification, expected) in mapOf(WakeNotificationResult.POSTED to PushDeliveryStatus.ALERT_REQUESTED,
                WakeNotificationResult.PERMISSION_DENIED to PushDeliveryStatus.PERMISSION_BLOCKED,
                WakeNotificationResult.APP_DISABLED to PushDeliveryStatus.PERMISSION_BLOCKED,
                WakeNotificationResult.CHANNEL_DISABLED to PushDeliveryStatus.CHANNEL_BLOCKED,
                WakeNotificationResult.FAILED to PushDeliveryStatus.UNAVAILABLE)) {
            assertEquals(expected, wakeDeliveryStatus(WakeReceipt(WakeReception.ACCEPTED, notification = notification)))
        }
    }
}
