package dev.sebastiano.remozio.android.updates

import android.content.pm.PackageInstaller
import kotlin.test.*
import org.junit.Test

class UpdateCallbackTest {
    private val nonce = "ab".repeat(32)
    private val binding = UpdateCallbackBinding(7, nonce)
    private fun decode(
        action: String? = UPDATE_STATUS_ACTION,
        data: String? = binding.uri,
        session: Int = 7,
        status: Int = PackageInstaller.STATUS_SUCCESS,
        preApproval: Boolean = false,
    ) = decodeUpdateCallback(action, data, session, status, preApproval)

    @Test fun canonicalBindingRoundTripsAndRequiresBothFields() {
        assertEquals(binding, UpdateCallbackBinding.parse(binding.uri))
        assertEquals(UpdateCallbackBinding(Int.MAX_VALUE, nonce), UpdateCallbackBinding.parse("remozio-update://session/2147483647/$nonce"))
        val record = UpdateRecord(nonce, "dev.sebastiano.remozio.android", 2, 7, UpdatePhase.INTENT)
        assertTrue(binding.matches(record))
        assertFalse(binding.matches(record.copy(sessionId = 8)))
        assertFalse(binding.matches(record.copy(nonce = "cd".repeat(32))))
    }

    @Test fun rejectsAlternateAndMalformedIdentities() {
        listOf(null, "", binding.uri + "?extra=1", binding.uri + "#fragment", binding.uri + "/",
            binding.uri.replace("/7/", "/07/"), binding.uri.replace("/7/", "/-1/"),
            binding.uri.replace("/7/", "/2147483648/"), binding.uri.replace("/7/", "/+7/"),
            binding.uri.replace("/7/", "/%37/"), binding.uri.uppercase(), binding.uri.dropLast(1),
            binding.uri.replace("session", "other"), "https://session/7/$nonce",
        ).forEach { assertNull(UpdateCallbackBinding.parse(it), it) }
    }

    @Test fun rejectsWrongActionSessionAndPreapprovalWithoutMutation() {
        assertNull(decode(action = null))
        assertNull(decode(action = UPDATE_CONFIRM_ACTION))
        assertNull(decode(session = -1))
        assertNull(decode(session = 8))
        assertNull(decode(preApproval = true))
    }

    @Test fun pendingConfirmationAndTerminalCodesHaveDistinctMeaning() {
        assertEquals(UpdatePhase.AWAITING_USER, decode(status = PackageInstaller.STATUS_PENDING_USER_ACTION)!!.phase)
        assertEquals(UpdatePhase.SUCCESS, decode()!!.phase)
        listOf(PackageInstaller.STATUS_FAILURE, PackageInstaller.STATUS_FAILURE_BLOCKED,
            PackageInstaller.STATUS_FAILURE_ABORTED, PackageInstaller.STATUS_FAILURE_INVALID,
            PackageInstaller.STATUS_FAILURE_CONFLICT, PackageInstaller.STATUS_FAILURE_STORAGE,
            PackageInstaller.STATUS_FAILURE_INCOMPATIBLE, PackageInstaller.STATUS_FAILURE_TIMEOUT,
        ).forEach { assertEquals(UpdatePhase.FAILURE, decode(status = it)!!.phase) }
    }

    @Test fun unknownOrMissingStatusDoesNotInventFailure() {
        listOf(Int.MIN_VALUE, Int.MAX_VALUE, -2, 99).forEach { assertNull(decode(status = it)) }
    }
}
