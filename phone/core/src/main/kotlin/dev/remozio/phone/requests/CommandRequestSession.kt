package dev.remozio.phone.requests

import dev.remozio.protocol.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class CommandSessionRejection { INVALID_SIGNATURE, WRONG_AUTHORITY, CLOSED }
class CommandSessionException(val reason: CommandSessionRejection) : IllegalArgumentException(reason.name)

data class RequestLimits(
    val body: CborLimits,
    val capture: CborLimits,
    val status: CborLimits,
    val signing: CborLimits,
)

data class CommandRequestSnapshot(val capture: CommandCapturePayload?, val status: TrackedRequestStatus?, val closed: Boolean = false)

/** Opaque identities use content equality and defensive copies. Display names are never keys. */
@ConsistentCopyVisibility
data class CommandRequestIdentity internal constructor(
    val macID: CborValue.Bytes,
    val accountID: CborValue.Bytes,
    val requestID: CborValue.Bytes,
)

/**
 * Owns one authenticated command capture in memory. A signature establishes origin, not current validity.
 * The enrollment owner must close this session when its trusted authority changes.
 */
class CommandRequestSession private constructor(
    capture: CommandCapturePayload,
    private val tracker: RequestStatusTracker,
    val identity: CommandRequestIdentity,
    internal val requestDigest: CborValue.Bytes,
    private val authorityKey: CborValue.Bytes,
    private val challenge: CborValue.Bytes,
    private val permittedActions: Set<CapturedAction>,
) : AutoCloseable {
    /** Public immutable digest for matching a local navigation hint to this authenticated request. */
    val issuedRequestDigest: CborValue.Bytes get() = requestDigest

    private var memory: CommandMemoryBudget.Reservation? = null
    private var capture: CommandCapturePayload? = capture

    @Synchronized
    internal fun retainMemory(budget: CommandMemoryBudget, replacing: CommandMemoryBudget.Reservation? = null, beforeCommit: () -> Unit = {}) {
        check(memory == null && !closure.value)
        val c = checkNotNull(capture)
        val elements = c.arguments.size.toLong() + c.environment.size.toLong() * 3 +
            c.ancestry.entries.size.toLong() * 2 + c.target.supplementaryGroups.size.toLong() +
            (if (c is LinuxCommandCapture) c.requester.credentials.supplementaryGroups.size.toLong() else 0L)
        memory = budget.retain(c.canonicalByteCount.toLong(), elements, replacing, beforeCommit)
    }
    @Synchronized
    internal fun terminalMemory(): CommandMemoryBudget.Reservation? {
        check(isTerminal())
        return memory
    }
    private val closure = MutableStateFlow(false)
    val closed: StateFlow<Boolean> = closure.asStateFlow()
    private val revision = MutableStateFlow(0uL)
    val revisions: StateFlow<ULong> = revision.asStateFlow()

    /** Removes the owned capture before notifying observers of a terminal update. */
    @Synchronized
    fun observe(body: ByteArray, signature: ByteArray, receivedAt: ElapsedInstant): StatusAcceptance {
        if (closure.value) throw CommandSessionException(CommandSessionRejection.CLOSED)
        val result = tracker.observe(body, signature, receivedAt)
        if (result == StatusAcceptance.APPLIED) {
            val status = checkNotNull(tracker.snapshot(receivedAt)).status
            if (status.phase.isTerminal) { capture = null; memory?.releaseCapture() }
            revision.value = status.revision
        }
        return result
    }

    /** Callers must replace old snapshots; clearing this owner cannot erase references held elsewhere. */
    @Synchronized
    fun snapshot(now: ElapsedInstant) = if (closure.value) CommandRequestSnapshot(null, null, closed = true)
        else CommandRequestSnapshot(capture, tracker.snapshot(now))

    fun isBoundToAuthority(macID: ByteArray, accountID: ByteArray, publicKey: ByteArray): Boolean =
        identity.macID == CborValue.Bytes(macID) && identity.accountID == CborValue.Bytes(accountID) &&
            authorityKey == CborValue.Bytes(publicKey)

    /** Runs a bound decision operation under the session monitor. The enrolled host still decides freshness and the winning phone. */
    @Synchronized
    fun <T> withPendingDecision(
        now: ElapsedInstant,
        phoneID: ByteArray,
        keyID: ByteArray,
        action: CapturedAction,
        operation: (DecisionPayload) -> T,
    ): T {
        check(!closure.value && capture != null)
        val tracked = checkNotNull(tracker.snapshot(now))
        check(tracked.status.phase == RequestPhase.QUEUED || tracked.status.phase == RequestPhase.PRESENTED)
        check(!tracked.timing.clockUncertain && (tracked.timing.authorizationRemainingUpperBoundMs ?: 0uL) > 0uL)
        ActionPolicy.requirement(action, RequestKind.COMMAND, permittedActions)
        return operation(DecisionPayload(identity.macID.copyBytes(), identity.accountID.copyBytes(), identity.requestID.copyBytes(),
            requestDigest.copyBytes(), challenge.copyBytes(), phoneID, keyID, action))
    }

    @Synchronized
    internal fun isTerminal(): Boolean = !closure.value && capture == null

    /** Local invalidation is not an authority-signed terminal result. Old UI handles must stop displaying it. */
    @Synchronized
    override fun close() {
        capture = null
        closure.value = true
        memory?.close(); memory = null
    }

    companion object {
        /** IDs and the key come from trusted enrollment. Schemas come from this authenticated channel; the legacy default is schema 1. */
        fun open(
            body: ByteArray,
            signature: ByteArray,
            expectedMacID: ByteArray,
            expectedAccountID: ByteArray,
            trustedAuthorityPublicKey: ByteArray,
            limits: RequestLimits,
            negotiatedSchemas: Set<ULong> = setOf(1u),
        ): CommandRequestSession {
            require(expectedMacID.size == 16 && expectedAccountID.size == 16)
            if (body.size > limits.body.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
            if (signature.size != 64) throw CommandSessionException(CommandSessionRejection.INVALID_SIGNATURE)
            val canonical = body.copyOf()
            val key = trustedAuthorityPublicKey.copyOf()
            if (!ApprovalSignature.verify(signature.copyOf(), key, 1u, ApprovalMessageType.REQUEST,
                    SigningPurpose.ISSUED_REQUEST, canonical, limits.body, limits.signing)) {
                throw CommandSessionException(CommandSessionRejection.INVALID_SIGNATURE)
            }
            require(negotiatedSchemas.isNotEmpty() && CommandCapturePayload.supportedSchemaVersions.containsAll(negotiatedSchemas))
            val capabilities = ContractCapabilities(negotiatedSchemas.associate { RequestContract(RequestKind.COMMAND, 1u, it) to emptySet<ULong>() })
            val request = IssuedRequestPayload.decode(canonical, limits.body, limits.capture, capabilities)
            if (!request.macID.contentEquals(expectedMacID) || !request.accountID.contentEquals(expectedAccountID)) {
                throw CommandSessionException(CommandSessionRejection.WRONG_AUTHORITY)
            }
            val capture = CommandCapturePayload.decode(request.canonicalCapture, limits.capture, expectedSchemaVersion = request.contract.schemaVersion)
            return CommandRequestSession(capture,
                RequestStatusTracker(request, key, limits.status, limits.signing, limits.body),
                CommandRequestIdentity(CborValue.Bytes(request.macID), CborValue.Bytes(request.accountID),
                    CborValue.Bytes(request.requestID)),
                CborValue.Bytes(request.requestDigest(limits.body, limits.signing)),
                CborValue.Bytes(key), CborValue.Bytes(request.challenge), request.permittedActions.toSet())
        }
    }
}
