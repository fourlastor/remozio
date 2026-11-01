package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/** Uses the real scheduling parser and verifier. This source set never enters application artifacts. */
suspend fun syntheticUpdateSchedulingChannel(
    record: StoredPhoneEnrollment,
    elapsedNanos: () -> Long,
    currentEnrollment: suspend () -> StoredPhoneEnrollment,
    reply: (PhoneUpdateSchedulingFrame) -> ByteArray,
): PhoneUpdateSchedulingChannel {
    val e = record.enrollment
    val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
    val peer = SyntheticUpdateSchedulingPeer(scope, reply)
    val raw = NegotiatedTLSChannel.connect(peer, scope, emptyList(), emptySet(), PhoneUpdateSchedulingFrame.MAXIMUM_BYTES,
        purpose = EnrolledChannelPurpose.UPDATE_SCHEDULING)
    return PhoneUpdateSchedulingChannel.bind(record, raw, elapsedNanos, currentEnrollment, 5000)
}

/** Exercises the explicit version2 parser and Root verifier on an owned byte stream. */
suspend fun syntheticUpdateSchedulingV2Channel(
    record: StoredPhoneEnrollment,
    elapsedNanos: () -> Long,
    currentEnrollment: suspend () -> StoredPhoneEnrollment,
    reply: (PhoneUpdateSchedulingFrame) -> ByteArray,
): PhoneUpdateSchedulingChannel {
    val e = record.enrollment
    val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
    val peer = SyntheticUpdateSchedulingPeer(scope, reply, version2 = true)
    val raw = NegotiatedTLSChannel.connect(peer, scope, emptyList(), emptySet(), PhoneUpdateSchedulingFrameV2.MAXIMUM_BYTES,
        purpose = EnrolledChannelPurpose.UPDATE_SCHEDULING_V2)
    return PhoneUpdateSchedulingChannel.bindV2(record, raw, elapsedNanos, currentEnrollment, 5000)
}

private class SyntheticUpdateSchedulingPeer(scope: ChannelScope,
    private val reply: (PhoneUpdateSchedulingFrame) -> ByteArray, private val version2: Boolean = false) : ApprovalByteStream {
    private val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, scope, ByteArray(32) { 12 }, setOf(1u), emptyList(), emptySet()), 1u)
    private val offer = owner.offer()
    private val output = ByteArrayOutputStream()
    private val input = ArrayDeque<ByteArray>()
    private var phase = 0
    private val maximum = if (version2) PhoneUpdateSchedulingFrameV2.MAXIMUM_BYTES else PhoneUpdateSchedulingFrame.MAXIMUM_BYTES
    override suspend fun awaitOpen() = Unit
    override suspend fun send(bytes: ByteArray) {
        output.write(bytes)
        val all = output.toByteArray()
        if (all.size < 4) return
        val count = ByteBuffer.wrap(all).int
        if (all.size < count + 4) return
        check(all.size == count + 4); output.reset()
        val body = all.copyOfRange(4, all.size)
        when (phase++) {
            0 -> { owner.receiveOffer(body); input.add(frame(offer)) }
            1 -> { owner.receiveConfirmation(body); input.add(frame(owner.confirmation())) }
            else -> {
                val envelope = SessionEnvelope.decode(body, maximum)
                check(envelope.sessionID == owner.confirmed().sessionID && envelope.sequence == 0uL)
                val request = if (version2) {
                    (PhoneUpdateSchedulingFrameV2.decode(envelope.payload.copyBytes()) as PhoneUpdateSchedulingFrameV2.Message).frame
                } else PhoneUpdateSchedulingFrame.decode(envelope.payload.copyBytes())
                input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), 0u, reply(request)).encode(maximum)))
            }
        }
    }
    override suspend fun receive(): ByteArray = input.removeFirst()
    override fun close() = owner.close()
    override suspend fun awaitClosed() = Unit
    private fun frame(bytes: ByteArray) = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
}
