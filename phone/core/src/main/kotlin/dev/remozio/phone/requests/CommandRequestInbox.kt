package dev.remozio.phone.requests

import dev.remozio.protocol.*
import java.util.Collections
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** In-memory ownership errors. These are not remote request outcomes. */
enum class InboxRejection { CLOSED, ALREADY_ENROLLED, STALE_ENROLLMENT, CAPACITY, CONFLICTING_REQUEST, UNKNOWN_REQUEST, RETIRED_REQUEST }
class InboxException(val reason: InboxRejection) : IllegalStateException(reason.name)

/**
 * Local trusted code installs enrollment handles. Request delivery cannot create or replace enrollment.
 * Limits bound the live window. Configured retirement releases only persisted terminal handles, never active requests.
 * The Mac still owns durable decision consumption and replay protection.
 */
class CommandRequestInbox(private val maximumEnrollments: Int, private val maximumRequestsPerEnrollment: Int,
    private val memoryBudget: CommandMemoryBudget? = null) : AutoCloseable {
    private data class Scope(val mac: CborValue.Bytes, val account: CborValue.Bytes)
    private val enrollments = linkedMapOf<Scope, CommandRequestEnrollment>()
    private var closed = false

    init { require(maximumEnrollments > 0 && maximumRequestsPerEnrollment > 0) }

    /** IDs/key must come from completed trusted enrollment, never an incoming request or peer advertisement. */
    @Synchronized
    fun add(macID: ByteArray, accountID: ByteArray, authorityKey: ByteArray, limits: RequestLimits,
            retired: RetiredCommandRequests? = null): CommandRequestEnrollment {
        checkOpen()
        val scope = scope(macID, accountID)
        if (scope in enrollments) reject(InboxRejection.ALREADY_ENROLLED)
        if (enrollments.size >= maximumEnrollments) reject(InboxRejection.CAPACITY)
        val enrollment = CommandRequestEnrollment(macID, accountID, authorityKey, limits, maximumRequestsPerEnrollment, retired, memoryBudget)
        enrollments[scope] = enrollment
        return enrollment
    }

    /** Explicit replacement after independently authorized trust changes; old network callbacks keep a closed handle. */
    @Synchronized
    fun replace(old: CommandRequestEnrollment, authorityKey: ByteArray, limits: RequestLimits): CommandRequestEnrollment {
        checkOpen()
        val scope = Scope(old.macID, old.accountID)
        if (enrollments[scope] !== old) reject(InboxRejection.STALE_ENROLLMENT)
        val replacement = CommandRequestEnrollment(old.macID.copyBytes(), old.accountID.copyBytes(),
            authorityKey, limits, maximumRequestsPerEnrollment, memoryBudget = memoryBudget)
        old.close()
        enrollments[scope] = replacement
        return replacement
    }

    /** A stale handle cannot remove a replacement enrollment. Other scopes remain untouched. */
    @Synchronized
    fun remove(enrollment: CommandRequestEnrollment): Boolean {
        val scope = Scope(enrollment.macID, enrollment.accountID)
        if (enrollments[scope] !== enrollment) return false
        enrollment.close()
        enrollments.remove(scope)
        return true
    }

    @Synchronized
    override fun close() {
        closed = true
        enrollments.values.forEach { it.close() }
        enrollments.clear()
    }

    private fun checkOpen() { if (closed) reject(InboxRejection.CLOSED) }
    private fun scope(macID: ByteArray, accountID: ByteArray): Scope {
        require(macID.size == 16 && accountID.size == 16)
        return Scope(CborValue.Bytes(macID), CborValue.Bytes(accountID))
    }
}

/** Holds requests for one trusted Mac/account incarnation. A replaced handle can never reopen. */
class CommandRequestEnrollment internal constructor(
    macID: ByteArray, accountID: ByteArray, authorityKey: ByteArray,
    internal val limits: RequestLimits, private val maximumRequests: Int,
    private val retired: RetiredCommandRequests? = null,
    private val memoryBudget: CommandMemoryBudget? = null,
) : AutoCloseable {
    val macID = CborValue.Bytes(macID)
    val accountID = CborValue.Bytes(accountID)
    private val authorityKey = authorityKey.copyOf()
    private val requests = linkedMapOf<CommandRequestIdentity, CommandRequestSession>()
    private var receiver: AutoCloseable? = null
    private val publishedSessions = MutableStateFlow<List<CommandRequestSession>>(emptyList())
    val requestSessions = publishedSessions.asStateFlow()
    private val limited = MutableStateFlow(false)
    /** A request was omitted during this connection attempt. No omitted capture is retained. */
    val capacityLimited = limited.asStateFlow()
    private var closed = false

    init { require(authorityKey.size == 65 && authorityKey[0] == 4.toByte()) }

    /** Even duplicates authenticate first. Reuse the existing owner instead of resetting its status or timing. */
    @Synchronized
    fun accept(body: ByteArray, signature: ByteArray): CommandRequestSession = acceptNegotiated(body, signature, setOf(1u))

    @Synchronized
    private fun acceptNegotiated(body: ByteArray, signature: ByteArray, schemas: Set<ULong>): CommandRequestSession =
        memoryBudget?.parse { acceptParsed(body, signature, schemas) } ?: acceptParsed(body, signature, schemas)

    private fun acceptParsed(body: ByteArray, signature: ByteArray, schemas: Set<ULong>): CommandRequestSession {
        if (closed) reject(InboxRejection.CLOSED)
        val candidate = CommandRequestSession.open(body, signature, macID.copyBytes(), accountID.copyBytes(), authorityKey, limits, schemas)
        try {
            val existing = requests[candidate.identity]
            if (existing != null) {
                candidate.close()
                if (existing.requestDigest != candidate.requestDigest) reject(InboxRejection.CONFLICTING_REQUEST)
                return existing
            }
            val remembered = retired?.lookup(candidate.identity.requestID.copyBytes())
            if (remembered != null) {
                if (!remembered.contentEquals(candidate.requestDigest.copyBytes())) reject(InboxRejection.CONFLICTING_REQUEST)
                reject(InboxRejection.RETIRED_REQUEST)
            }
            var terminal = if (requests.size >= maximumRequests) {
                (if (retired == null) null else requests.entries.firstOrNull { it.value.isTerminal() })
                    ?: reject(InboxRejection.CAPACITY)
            } else null
            val persistRetirement = {
                terminal?.let {
                    checkNotNull(retired).remember(it.key.requestID.copyBytes(), it.value.requestDigest.copyBytes())
                }
                Unit
            }
            if (memoryBudget != null) {
                try {
                    candidate.retainMemory(memoryBudget, terminal?.value?.terminalMemory(), persistRetirement)
                } catch (failure: InboxException) {
                    if (failure.reason != InboxRejection.CAPACITY || terminal != null) throw failure
                    terminal = (if (retired == null) null else requests.entries.firstOrNull { it.value.isTerminal() })
                        ?: throw failure
                    candidate.retainMemory(memoryBudget, terminal.value.terminalMemory(), persistRetirement)
                }
            } else persistRetirement()
            terminal?.let {
                requests.remove(it.key)
                it.value.close()
            }
            requests[candidate.identity] = candidate
            publishedSessions.value = Collections.unmodifiableList(requests.values.toList())
            return candidate
        } catch (failure: Throwable) {
            candidate.close()
            throw failure
        }
    }

    /** Local ownership handoff only. Reconnect keeps the existing request window. */
    @Synchronized
    internal fun attach(owner: AutoCloseable) {
        if (closed) reject(InboxRejection.CLOSED)
        val previous = receiver
        receiver = owner
        limited.value = false
        previous?.close()
    }

    /** Background delivery can claim only an idle owner. Foreground attachment keeps its existing replacement behavior. */
    @Synchronized
    internal fun attachIfIdle(owner: AutoCloseable): Boolean {
        if (closed) reject(InboxRejection.CLOSED)
        if (receiver != null) return false
        receiver = owner
        limited.value = false
        return true
    }

    @Synchronized
    internal fun detach(owner: AutoCloseable) { if (receiver === owner) receiver = null }

    /** The identity check and state update share the enrollment monitor with replacement and removal. */
    @Synchronized
    internal fun deliver(owner: AutoCloseable, message: ApprovalMessage, receivedAt: ElapsedInstant, schemas: Set<ULong>): Boolean {
        if (closed || receiver !== owner) reject(InboxRejection.STALE_ENROLLMENT)
        val body = message.body.copyBytes()
        val signature = message.signature.copyBytes()
        when (message.type) {
            ApprovalMessageType.REQUEST -> try { acceptNegotiated(body, signature, schemas) } catch (failure: InboxException) {
                when (failure.reason) {
                    InboxRejection.CAPACITY -> limited.value = true
                    InboxRejection.RETIRED_REQUEST -> Unit
                    else -> throw failure
                }
            }
            ApprovalMessageType.STATUS -> {
                val claim = RequestStatusPayload.decode(body, limits.status)
                val key = CommandRequestIdentity(CborValue.Bytes(claim.macID), CborValue.Bytes(claim.accountID),
                    CborValue.Bytes(claim.requestID))
                val session = requests[key]
                if (session != null) session.observe(body, signature, receivedAt)
                else {
                    val digest = retired?.lookup(claim.requestID)
                    if (digest == null && !limited.value) reject(InboxRejection.UNKNOWN_REQUEST)
                    require(claim.macID.contentEquals(macID.copyBytes()) && claim.accountID.contentEquals(accountID.copyBytes()))
                    if (digest != null) require(claim.requestDigest.contentEquals(digest))
                    require(ApprovalSignature.verify(signature, authorityKey, 1u, ApprovalMessageType.STATUS, SigningPurpose.STATUS,
                        body, limits.status, limits.signing))
                    // Unowned statuses are authenticated but cannot create a request or grant action authority.
                }
            }
            ApprovalMessageType.DECISION -> throw IllegalArgumentException("Unexpected inbound decision")
        }
        return limited.value
    }

    /** Snapshot of owned handles, including terminal tombstones. Capture contents remain owned by each session. */
    @Synchronized
    fun sessions(): List<CommandRequestSession> = requests.values.toList()

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        receiver?.close()
        receiver = null
        requests.values.forEach { it.close() }
        requests.clear()
        publishedSessions.value = emptyList()
        retired?.close()
    }
}

private fun reject(reason: InboxRejection): Nothing = throw InboxException(reason)
