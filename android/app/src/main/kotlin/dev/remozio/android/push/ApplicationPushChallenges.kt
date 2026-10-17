package dev.remozio.android.push

import dev.remozio.phone.push.PendingPushChallengeTicket
import dev.remozio.protocol.PhonePushRegistrationMetadata
import dev.remozio.protocol.PushData
import java.util.UUID

internal class PushChallengeMoment(val bootEpoch: ULong, val milliseconds: ULong)
internal interface PushChallengeOwner : AutoCloseable {
    fun selectGeneration(generation: UUID, moment: PushChallengeMoment)
    fun admit(generation: UUID, challenge: PushData.TokenChallenge, moment: PushChallengeMoment): PendingPushChallengeTicket?
    fun pending(generation: UUID, moment: PushChallengeMoment): List<PendingPushChallengeTicket>
    fun match(generation: UUID, metadata: PhonePushRegistrationMetadata, moment: PushChallengeMoment): PushData.TokenChallenge?
    fun discard(ticket: PendingPushChallengeTicket, moment: PushChallengeMoment): Boolean
}

/** Provider lock precedes this owner. Ingress performs local durable admission before any work is enqueued. */
internal class ApplicationPushChallenges(private val provider: PushClientOwner, private val clock: () -> PushChallengeMoment,
                                         private val open: () -> PushChallengeOwner) : AutoCloseable {
    private var owner: PushChallengeOwner? = null
    private var closed = false
    fun admit(generation: UUID, challenge: PushData.TokenChallenge): PendingPushChallengeTicket? =
        current(generation) { journal, now -> journal.admit(generation, challenge, now) }
    fun pending(generation: UUID): List<PendingPushChallengeTicket> =
        current(generation) { journal, now -> journal.pending(generation, now) } ?: emptyList()
    /** The caller checks current enrollment, provider token revision and authenticated metadata under enrollmentAccess. */
    fun match(generation: UUID, metadata: PhonePushRegistrationMetadata): PushData.TokenChallenge? =
        current(generation) { journal, now -> journal.match(generation, metadata, now) }
    fun discard(ticket: PendingPushChallengeTicket): Boolean =
        current(ticket.generation) { journal, now -> journal.discard(ticket, now) } ?: false

    private fun <T> current(generation: UUID, body: (PushChallengeOwner, PushChallengeMoment) -> T): T? =
        provider.withCurrent(generation) { access { journal ->
            val now = clock(); journal.selectGeneration(generation, now); body(journal, now)
        } }
    @Synchronized private fun <T> access(body: (PushChallengeOwner) -> T): T {
        check(!closed)
        try { return body(owner ?: open().also { owner = it }) }
        catch (failure: Exception) {
            val previous = owner; owner = null
            try { previous?.close() } catch (closing: Exception) { failure.addSuppressed(closing) }
            throw failure
        }
    }
    @Synchronized override fun close() { if (!closed) { closed = true; val previous = owner; owner = null; previous?.close() } }
}
