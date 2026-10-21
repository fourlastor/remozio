package dev.remozio.android.requests

import dev.remozio.phone.requests.CommandRequestSession
import dev.remozio.protocol.CborValue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOf

internal fun commandIdentityText(id: CborValue.Bytes) = id.copyBytes().joinToString("") { "%02x".format(it) }

/** Selection retains the authenticated session and its exact connection, independently of list filters. */
internal class ScopedCommandRequest(val owner: StoredCommandOwner, val session: CommandRequestSession) {
    val connection = checkNotNull(owner.connection)
    init {
        val e = connection.record.enrollment
        require(e.recordID == owner.recordID && e.macID == owner.macID && e.accountID == owner.accountID)
        require(session.isBoundToAuthority(owner.macID.copyBytes(), owner.accountID.copyBytes(), e.authorityPublicKey.copyBytes()))
    }
    val key = listOf(owner.recordID, owner.macID, owner.accountID, session.identity.requestID)
        .joinToString(":", transform = ::commandIdentityText)

    fun isCurrent(owners: List<StoredCommandOwner>) = !session.closed.value && connection.requests.value.any { it === session } && owners.any {
        it.recordID == owner.recordID && it.macID == owner.macID && it.accountID == owner.accountID && it.connection === connection
    }
    override fun toString() = "ScopedCommandRequest(redacted)"
}

/** This projection only observes authenticated owners. It never opens, closes or retries a connection. */
@OptIn(ExperimentalCoroutinesApi::class)
internal fun observeCommandInbox(owners: List<StoredCommandOwner>): Flow<List<ScopedCommandRequest>> {
    val connected = owners.filter { it.connection != null }
    if (connected.isEmpty()) return flowOf(emptyList())
    return combine(connected.map { owner -> checkNotNull(owner.connection).requests.flatMapLatest { sessions ->
        if (sessions.isEmpty()) flowOf(emptyList()) else combine(sessions.map { session ->
            combine(session.revisions, session.closed) { _, _ -> ScopedCommandRequest(owner, session) }
        }) { it.toList() }
    } }) { it.flatMap { requests -> requests } }
}

/** Equal labels gain identity suffixes. Prefix collisions expand until the distinct IDs are visible. */
internal fun commandMacLabel(owner: StoredCommandOwner, owners: List<StoredCommandOwner>): String {
    val peers = owners.filter { it.label == owner.label }.map { it.macID }.distinct()
    return if (peers.size <= 1) owner.label else "${owner.label} · ${commandIdentitySuffix(owner.macID, peers)}"
}

internal fun commandAccountSuffix(owner: StoredCommandOwner, owners: List<StoredCommandOwner>): String =
    commandIdentitySuffix(owner.accountID, owners.filter { it.macID == owner.macID }.map { it.accountID }.distinct())

private fun commandIdentitySuffix(id: CborValue.Bytes, peers: List<CborValue.Bytes>): String {
    val full = commandIdentityText(id)
    val others = peers.filter { it != id }.map(::commandIdentityText)
    val length = (8..full.length).first { length -> others.none { it.take(length) == full.take(length) } }
    return full.take(length)
}
