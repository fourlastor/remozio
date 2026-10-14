package dev.remozio.phone.transport

import dev.remozio.protocol.*
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.KeyManager
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex

private class PairingTLSStream(private val session: TLSRecordSession) : ApprovalByteStream {
    override suspend fun awaitOpen() = session.awaitOpen()
    override suspend fun send(bytes: ByteArray) = session.send(bytes)
    override suspend fun receive(): ByteArray? = session.receive()
    override fun close() = session.close()
    override suspend fun awaitClosed() = session.closeAndJoin()
}

/** One restricted setup exchange. The Android host independently verifies and persists the transcript before submitting its hardware proof. */
class PairingSetupChannel private constructor(
    private val owner: Job, scope: CoroutineScope, private val stream: ApprovalByteStream,
    private val invitation: PairingInvitation, private val proposal: PairingPhoneProposal, timeoutMillis: Long,
) : AutoCloseable {
    private enum class State { OPENING, AUTHENTICATED, PROPOSAL_SENT, STAGED, PROOF_SUBMITTED, FINISHED }
    private val closed = AtomicBoolean(false)
    private val operationLock = Mutex()
    private var state = State.OPENING
    private var staged: PairingTranscript? = null
    private var pending = ByteArray(0)
    private var offset = 0
    private val deadline: Job
    init {
        require(timeoutMillis in 1..300_000)
        proposal.validateMacScope(invitation)
        require(CompatibilityPolicy.envelopeVersion(setOf(1u), proposal.phone.envelopeVersions, invitation.minimumEnvelopeVersion) == 1uL)
        deadline = scope.launch { delay(timeoutMillis); close() }
        scope.launch(Dispatchers.Unconfined, start = CoroutineStart.UNDISPATCHED) {
            try { awaitCancellation() } finally { close() }
        }
    }
    val transcript: PairingTranscript get() = checkNotNull(staged)

    private suspend fun authenticate() = operation {
        check(state == State.OPENING)
        stream.awaitOpen(); active()
        check(read() == PairingSetupFrame.Hello)
        state = State.AUTHENTICATED
    }

    /** Start the sole proposal only after selecting an authenticated route. Human setup has its own longer deadline. */
    suspend fun awaitTranscript(): PairingTranscript = operation {
        check(state == State.AUTHENTICATED)
        state = State.PROPOSAL_SENT
        write(PairingSetupFrame.Proposal(proposal))
        val frame = read() as? PairingSetupFrame.Transcript ?: throw IOException("Missing pairing transcript")
        invitation.validateMacClaims(frame.value); proposal.validate(frame.value)
        require(frame.value.selectedEnvelopeVersion == 1uL && frame.value.expiresAtUnixMillis - frame.value.issuedAtUnixMillis <= 300_000uL)
        staged = frame.value; state = State.STAGED
        frame.value
    }

    /** Call once after human confirmation, durable PREPARED storage and a fresh hardware biometric proof.
     * A lost reply is ambiguous. This method never repeats the submission or activates an enrollment. */
    suspend fun submitProof(confirmedDigest: ByteArray, biometricProof: ByteArray): ByteArray = operation {
        check(state == State.STAGED)
        val transcript = checkNotNull(staged)
        require(confirmedDigest.contentEquals(transcript.digest()))
        require(transcript.verify(biometricProof, transcript.biometricKey.publicKey.copyBytes(), PairingProofPurpose.PHONE_BIOMETRIC))
        state = State.PROOF_SUBMITTED
        write(PairingSetupFrame.Proof(transcript.setupID.copyBytes(), transcript.digest(), biometricProof))
        val receipt = read() as? PairingSetupFrame.Receipt ?: throw IOException("Missing pairing receipt")
        require(receipt.setupID == transcript.setupID && receipt.digest == CborValue.Bytes(transcript.digest()))
        require(transcript.verify(receipt.signature.copyBytes(), invitation.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
        state = State.FINISHED; deadline.cancel()
        receipt.signature.copyBytes()
    }
    override fun close() {
        if (closed.compareAndSet(false, true)) { stream.close(); owner.cancel() }
    }
    suspend fun closeAndJoin() { close(); stream.awaitClosed(); owner.join() }
    override fun toString() = "PairingSetupChannel(redacted)"

    private suspend fun <T> operation(body: suspend () -> T): T {
        if (!operationLock.tryLock()) throw IOException("Pairing operation busy")
        try { active(); return body().also { active() } }
        catch (failure: Throwable) { close(); throw failure }
        finally { operationLock.unlock() }
    }
    private suspend fun active() { currentCoroutineContext().ensureActive(); check(!closed.get()) }
    private suspend fun write(frame: PairingSetupFrame) {
        active(); val bytes = frame.encode(); val size = bytes.size
        stream.send(byteArrayOf((size ushr 24).toByte(), (size ushr 16).toByte(), (size ushr 8).toByte(), size.toByte()))
        var position = 0
        while (position < size) {
            active(); val end = minOf(position + 32_768, size)
            stream.send(bytes.copyOfRange(position, end)); active(); position = end
        }
    }
    private suspend fun read(): PairingSetupFrame {
        val header = exact(4)
        val length = header.fold(0L) { value, byte -> (value shl 8) or (byte.toLong() and 255) }
        require(length in 1..PairingSetupFrame.MAXIMUM_BYTES.toLong())
        return PairingSetupFrame.decode(exact(length.toInt()))
    }
    private suspend fun exact(size: Int): ByteArray {
        val result = ByteArray(size); var position = 0
        while (position < size) {
            active()
            if (offset == pending.size) {
                val next = stream.receive() ?: throw IOException("Truncated pairing frame")
                active(); require(next.size in 1..32_768); pending = next; offset = 0
            }
            val count = minOf(size - position, pending.size - offset)
            pending.copyInto(result, position, offset, offset + count); position += count; offset += count
        }
        return result
    }
    companion object {
        /** The carrier is untrusted. Fresh TLS authenticates the invitation pin with the separate pairing ALPN.
         * The Android caller supplies its newly created hardware transport key manager. */
        suspend fun connect(parent: CoroutineScope, carrier: EncryptedRecordTransport, localKeys: Array<KeyManager>,
            invitation: PairingInvitation, proposal: PairingPhoneProposal, timeoutMillis: Long = 300_000,
        ): PairingSetupChannel {
            val channel = authenticate(parent, carrier, localKeys, invitation, proposal, timeoutMillis)
            try { channel.awaitTranscript(); return channel }
            catch (failure: Throwable) {
                withContext(NonCancellable) { channel.closeAndJoin() }
                throw failure
            }
        }

        /** Only pinned TLS and the restricted hello are read here. No phone proposal or enrollment action is sent. */
        suspend fun authenticate(parent: CoroutineScope, carrier: EncryptedRecordTransport, localKeys: Array<KeyManager>,
            invitation: PairingInvitation, proposal: PairingPhoneProposal, timeoutMillis: Long = 300_000,
        ): PairingSetupChannel {
            val owner = SupervisorJob(requireNotNull(parent.coroutineContext[Job]))
            val scope = CoroutineScope(owner + Dispatchers.IO)
            var engine: PinnedTLSClient? = null
            var session: TLSRecordSession? = null
            var result: PairingSetupChannel? = null
            try {
                proposal.validateMacScope(invitation)
                val prefix = byteArrayOf(0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x02,0x01,
                    0x06,0x08,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x03,0x01,0x07,0x03,0x42,0x00)
                engine = PinnedTLSClient(localKeys, prefix + invitation.transportPublicKey.copyBytes(),
                    PairingSetupFrame.APPLICATION_PROTOCOL, 1_048_576)
                session = TLSRecordSession(scope, engine, carrier)
                result = PairingSetupChannel(owner, scope, PairingTLSStream(session), invitation, proposal, timeoutMillis)
                result.authenticate(); return result
            } catch (failure: Throwable) {
                owner.cancel()
                withContext(NonCancellable) {
                    when { result != null -> result.closeAndJoin(); session != null -> session.closeAndJoin(); else -> { carrier.close(); carrier.awaitClosed(); engine?.close() } }
                    owner.join()
                }
                throw failure
            }
        }
        internal suspend fun authenticate(parent: CoroutineScope, stream: ApprovalByteStream, invitation: PairingInvitation,
            proposal: PairingPhoneProposal, timeoutMillis: Long = 300_000,
        ): PairingSetupChannel {
            val owner = SupervisorJob(requireNotNull(parent.coroutineContext[Job]))
            val scope = CoroutineScope(owner + Dispatchers.IO)
            var result: PairingSetupChannel? = null
            try {
                result = PairingSetupChannel(owner, scope, stream, invitation, proposal, timeoutMillis)
                result.authenticate(); return result
            } catch (failure: Throwable) {
                withContext(NonCancellable) {
                    if (result != null) result.closeAndJoin() else { stream.close(); stream.awaitClosed(); owner.cancel(); owner.join() }
                }
                throw failure
            }
        }
        // Injected streams cannot prove TLS peer identity or hardware key custody.
        internal suspend fun connect(parent: CoroutineScope, stream: ApprovalByteStream, invitation: PairingInvitation,
            proposal: PairingPhoneProposal, timeoutMillis: Long = 300_000,
        ): PairingSetupChannel {
            val owner = SupervisorJob(requireNotNull(parent.coroutineContext[Job]))
            val scope = CoroutineScope(owner + Dispatchers.IO)
            var result: PairingSetupChannel? = null
            try {
                result = PairingSetupChannel(owner, scope, stream, invitation, proposal, timeoutMillis)
                result.authenticate(); result.awaitTranscript(); return result
            } catch (failure: Throwable) { if (result != null) result.close() else { stream.close(); owner.cancel() }; throw failure }
        }
    }
}
