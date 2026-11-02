package dev.remozio.phone.transport

import dev.remozio.phone.audit.AuditHistoryQuery
import dev.remozio.phone.audit.AuditPageQuery
import dev.remozio.phone.audit.AuditQuery
import dev.remozio.phone.audit.AuditSyncSession
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeout

sealed interface PhoneAuditResult {
    class Failure internal constructor(val query: AuditQuery, val reason: PhoneAuditFailure) : PhoneAuditResult

    /** Carrier correlation is not evidence verification. Only the original sync session can accept this query. */
    class Unverified internal constructor(
        val query: AuditQuery,
        private val record: StoredPhoneEnrollment,
        private val body: CborValue.Bytes,
        private val signed: CborValue.Bytes,
    ) : PhoneAuditResult {
        val canonicalBody: ByteArray get() = body.copyBytes()
        val signature: ByteArray get() = signed.copyBytes()
        fun matchesEnrollment(current: StoredPhoneEnrollment): Boolean =
            current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current)

        /** The application serializes current enrollment and cache ownership around this handoff. */
        fun acceptInto(session: AuditSyncSession, current: StoredPhoneEnrollment) {
            require(matchesEnrollment(current))
            session.accept(query, canonicalBody, signature)
        }
        override fun toString() = "PhoneAuditResult.Unverified(redacted)"
    }
}

/** One audit query over enrolled TLS. The sync receiver owns query lifetime, verification and durable evidence. */
class PhoneAuditChannel private constructor(
    private val record: StoredPhoneEnrollment,
    private val channel: NegotiatedTLSChannel,
    private val timeoutMillis: Long,
    private val clock: () -> ElapsedInstant,
) : AutoCloseable {
    private val used = AtomicBoolean(false)

    suspend fun exchange(query: AuditQuery): PhoneAuditResult {
        try {
            check(used.compareAndSet(false, true))
            return withTimeout(timeoutMillis) {
                val started = clock()
                val request = when (query) {
                    is AuditHistoryQuery -> PhoneAuditFrame.HistoryQuery(query.queryNonce, query.requestedEpoch, query.requestedAfter)
                    is AuditPageQuery -> PhoneAuditFrame.PageQuery(query.queryNonce, query.journalEpoch, query.epochCreationGeneration, query.requestedAfter)
                }
                channel.send(request.encode())
                val reply = PhoneAuditFrame.decode(channel.receive() ?: throw IOException("Missing audit response"))
                require(reply.queryNonce == request.queryNonce)
                val result = when (reply) {
                    is PhoneAuditFrame.Failure -> PhoneAuditResult.Failure(query, reply.reason)
                    is PhoneAuditFrame.HistoryResponse -> {
                        require(query is AuditHistoryQuery)
                        PhoneAuditResult.Unverified(query, record, reply.canonicalPayload, reply.signature)
                    }
                    is PhoneAuditFrame.PageResponse -> {
                        require(query is AuditPageQuery)
                        PhoneAuditResult.Unverified(query, record, reply.canonicalPayload, reply.signature)
                    }
                    else -> throw IOException("Invalid audit response role")
                }
                val sampled = clock()
                require(sampled.epoch == started.epoch && sampled.milliseconds >= started.milliseconds &&
                    sampled.milliseconds - started.milliseconds < timeoutMillis.toULong())
                result
            }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { throw IOException("Audit unavailable") }
        finally { close() }
    }
    override fun close() = channel.close()
    suspend fun closeAndJoin() = channel.closeAndJoin()
    override fun toString() = "PhoneAuditChannel(redacted)"

    companion object {
        /** Supply an elapsed clock that includes device sleep and changes epoch when its origin changes. */
        fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, clock: () -> ElapsedInstant,
                 timeoutMillis: Long = 5_000): PhoneAuditChannel {
            try {
                require(record.phase == EnrollmentPhase.ACTIVE && timeoutMillis in 1..60_000)
                val e = record.enrollment
                val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
                val peer = channel.negotiated
                require(channel.purpose == EnrolledChannelPurpose.AUDIT && channel.localRequests.isEmpty() &&
                    1uL in channel.localAuditVersions && channel.maximumPayloadBytes in
                    (PhoneAuditFrame.OVERHEAD_BYTES + 1)..PhoneAuditFrame.MAXIMUM_BYTES)
                require(peer.peer.role == ChannelRole.MAC && peer.peer.scope == scope && peer.envelopeVersion == 1uL &&
                    peer.envelopeVersion >= (record.pairing?.minimumEnvelopeVersion ?: 1uL) &&
                    peer.peer.requests.isEmpty() && 1uL in peer.peer.auditVersions)
                return PhoneAuditChannel(record, channel, timeoutMillis, clock)
            } catch (failure: Exception) { channel.close(); throw failure }
        }
    }
}
