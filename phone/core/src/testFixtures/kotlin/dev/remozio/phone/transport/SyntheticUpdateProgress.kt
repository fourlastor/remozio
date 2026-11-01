package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.ChannelNegotiation
import dev.remozio.protocol.ChannelOffer
import dev.remozio.protocol.ChannelRole
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PhoneUpdateProgressFrame
import dev.remozio.protocol.SessionEnvelope
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/** Uses the real progress parser and Root verifier in the test fixture source set. */
suspend fun syntheticUpdateProgressChannel(
    record: StoredPhoneEnrollment,
    elapsedNanos: () -> Long,
    currentEnrollment: suspend () -> StoredPhoneEnrollment,
    reply: (PhoneUpdateProgressFrame.Status) -> ByteArray,
): PhoneUpdateProgressChannel {
    val e = record.enrollment
    val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
    val peer = SyntheticUpdateProgressPeer(scope, reply)
    val raw = NegotiatedTLSChannel.connect(peer, scope, emptyList(), emptySet(), PhoneUpdateProgressFrame.MAXIMUM_BYTES,
        purpose = EnrolledChannelPurpose.UPDATE_PROGRESS)
    return PhoneUpdateProgressChannel.bind(record, raw, elapsedNanos, currentEnrollment, 5000)
}

private class SyntheticUpdateProgressPeer(
    scope: ChannelScope,
    private val reply: (PhoneUpdateProgressFrame.Status) -> ByteArray,
) : ApprovalByteStream {
    private val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, scope, ByteArray(32) { 12 },
        setOf(1u), emptyList(), emptySet()), 1u)
    private val offer = owner.offer()
    private val output = ByteArrayOutputStream()
    private val input = ArrayDeque<ByteArray>()
    private var phase = 0
    override suspend fun awaitOpen() = Unit
    override suspend fun send(bytes: ByteArray) {
        output.write(bytes)
        val all = output.toByteArray()
        if (all.size < 4) return
        val count = ByteBuffer.wrap(all).int
        if (all.size < count + 4) return
        check(all.size == count + 4)
        output.reset()
        val body = all.copyOfRange(4, all.size)
        when (phase++) {
            0 -> { owner.receiveOffer(body); input.add(frame(offer)) }
            1 -> { owner.receiveConfirmation(body); input.add(frame(owner.confirmation())) }
            else -> {
                val maximum = PhoneUpdateProgressFrame.MAXIMUM_BYTES
                val envelope = SessionEnvelope.decode(body, maximum)
                check(envelope.sessionID == owner.confirmed().sessionID && envelope.sequence == 0uL)
                val request = PhoneUpdateProgressFrame.decode(envelope.payload.copyBytes()) as PhoneUpdateProgressFrame.Status
                input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), 0u, reply(request)).encode(maximum)))
            }
        }
    }
    override suspend fun receive(): ByteArray = input.removeFirst()
    override fun close() = owner.close()
    override suspend fun awaitClosed() = Unit
    private fun frame(bytes: ByteArray) = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
}
