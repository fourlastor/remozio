package dev.remozio.android.requests

import dev.remozio.protocol.CborValue

/** Navigation hint only. A matching authenticated session must be found before displaying a request. */
internal class CommandNotificationTarget(
    val recordID: CborValue.Bytes,
    val macID: CborValue.Bytes,
    val accountID: CborValue.Bytes,
    val epoch: CborValue.Bytes,
    val requestID: CborValue.Bytes,
    val digest: CborValue.Bytes,
) {
    init {
        require(listOf(recordID, macID, accountID, epoch, requestID).all { it.copyBytes().size == 16 })
        require(digest.copyBytes().size == 32)
    }
    fun encode() = PREFIX + listOf(recordID, macID, accountID, epoch, requestID, digest).joinToString(":", transform = ::commandIdentityText)
    fun matchesOwner(owner: StoredCommandOwner): Boolean = owner.recordID == recordID && owner.macID == macID &&
        owner.accountID == accountID && owner.connection?.record?.enrollment?.epoch == epoch
    fun matches(request: ScopedCommandRequest): Boolean = matchesOwner(request.owner) && request.session.identity.requestID == requestID &&
        request.session.issuedRequestDigest == digest
    override fun toString() = "CommandNotificationTarget(redacted)"
    companion object {
        private const val PREFIX = "remozio:request:v1:"
        fun from(request: ScopedCommandRequest) = CommandNotificationTarget(request.owner.recordID, request.owner.macID,
            request.owner.accountID, request.connection.record.enrollment.epoch, request.session.identity.requestID, request.session.issuedRequestDigest)
        fun decode(value: String?): CommandNotificationTarget? {
            if (value == null || value.length != PREFIX.length + 32 * 5 + 64 + 5 || !value.startsWith(PREFIX)) return null
            val fields = value.removePrefix(PREFIX).split(':')
            if (fields.size != 6 || fields.withIndex().any { (i, field) -> field.length != if (i == 5) 64 else 32 } ||
                fields.any { field -> field.any { it !in '0'..'9' && it !in 'a'..'f' } }) return null
            fun bytes(i: Int) = CborValue.Bytes(fields[i].chunked(2).map { it.toInt(16).toByte() }.toByteArray())
            return CommandNotificationTarget(bytes(0), bytes(1), bytes(2), bytes(3), bytes(4), bytes(5))
        }
    }
}
