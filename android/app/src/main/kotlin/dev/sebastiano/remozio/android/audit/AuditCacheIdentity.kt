package dev.sebastiano.remozio.android.audit

import dev.remozio.phone.audit.AuditCacheBinding
import java.security.MessageDigest

/** Version 1 remains readable. Version 2 separates authority keys for the same Mac/account. */
internal object AuditCacheIdentity {
    fun legacy(binding: AuditCacheBinding): String = digest(binding.macID + binding.accountID)
    fun current(binding: AuditCacheBinding): String = digest("dev.remozio.audit-cache-binding.v2".encodeToByteArray() +
        binding.macID + binding.accountID + binding.authorityPublicKey)
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }
}
