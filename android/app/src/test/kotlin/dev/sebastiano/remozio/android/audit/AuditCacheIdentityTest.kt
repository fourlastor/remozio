package dev.sebastiano.remozio.android.audit

import dev.remozio.phone.audit.AuditCacheBinding
import java.security.MessageDigest
import kotlin.test.*

class AuditCacheIdentityTest {
    private fun binding(mac: Int = 1, account: Int = 2, root: Int = 3) = AuditCacheBinding(
        ByteArray(16) { mac.toByte() }, ByteArray(16) { account.toByte() },
        byteArrayOf(4) + ByteArray(64) { root.toByte() })

    @Test fun legacyIdentityKeepsTheOriginalMacAndAccountPath() {
        val binding = binding()
        val original = MessageDigest.getInstance("SHA-256").digest(binding.macID + binding.accountID)
            .joinToString("") { "%02x".format(it) }
        assertEquals(original, AuditCacheIdentity.legacy(binding))
        assertEquals(original, AuditCacheIdentity.legacy(binding(root = 9)))
    }

    @Test fun currentIdentitySeparatesEachMacAccountAndRootWithoutChangingLegacyIdentity() {
        val first = AuditCacheIdentity.current(binding())
        assertEquals(64, first.length)
        assertTrue(first.all { it in '0'..'9' || it in 'a'..'f' })
        assertEquals(first, AuditCacheIdentity.current(binding()))
        for (different in listOf(binding(mac = 9), binding(account = 9), binding(root = 9))) {
            assertNotEquals(first, AuditCacheIdentity.current(different))
        }
        assertNotEquals(first, AuditCacheIdentity.legacy(binding()))
    }
}
