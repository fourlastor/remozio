@file:OptIn(ExperimentalAtomicApi::class)

package dev.remozio.pairing

import dev.remozio.protocol.*
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.io.IOException

/** One restricted setup exchange. The Android host independently verifies and persists the transcript before submitting its hardware proof. */
class PairingSetupChannel private constructor(
    private val owner: Job, scope: CoroutineScope, private val stream: PairingByteStream,
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
        require(selectEnvelopeVersion(setOf(1u), proposal.phone.envelopeVersions, invitation.minimumEnvelopeVersion) == 1uL)
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
    private suspend fun active() { currentCoroutineContext().ensureActive(); check(!closed.load()) }
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
        /** Opens the stream inside the channel's own scope, so one owner job covers the stream and the channel.
         * The caller authenticates the peer in [open] (pinned TLS with the pairing ALPN). The opener releases
         * what it created if it throws or is cancelled, and it must be cancellable. Only the restricted hello is read here: no proposal or enrollment action is sent. */
        suspend fun authenticate(parent: CoroutineScope, invitation: PairingInvitation, proposal: PairingPhoneProposal,
            timeoutMillis: Long = 300_000, open: suspend (CoroutineScope) -> PairingByteStream,
        ): PairingSetupChannel {
            val owner = SupervisorJob(requireNotNull(parent.coroutineContext[Job]))
            val scope = CoroutineScope(owner + Dispatchers.IO)
            var opening: Deferred<PairingByteStream>? = null
            var result: PairingSetupChannel? = null
            try {
                // The opener runs under the setup budget and under the parent: a stuck open can outlive neither.
                require(timeoutMillis in 1..300_000)
                val started = scope.async { open(scope) }
                opening = started
                val opened = withTimeout(timeoutMillis) { started.await() }
                result = PairingSetupChannel(owner, scope, opened, invitation, proposal, timeoutMillis)
                result.authenticate(); return result
            } catch (failure: Throwable) {
                owner.cancel()
                withContext(NonCancellable) {
                    if (result != null) result.closeAndJoin() else opening?.let { started ->
                        started.cancelAndJoin()
                        // The opener may have finished just before the cancellation. Nobody else owns that stream.
                        @OptIn(ExperimentalCoroutinesApi::class)
                        if (started.getCompletionExceptionOrNull() == null) started.getCompleted().let { it.close(); it.awaitClosed() }
                    }
                    owner.join()
                }
                throw failure
            }
        }

        /** Like [authenticate], then sends the proposal and waits for the transcript. */
        suspend fun connect(parent: CoroutineScope, invitation: PairingInvitation, proposal: PairingPhoneProposal,
            timeoutMillis: Long = 300_000, open: suspend (CoroutineScope) -> PairingByteStream,
        ): PairingSetupChannel {
            val channel = authenticate(parent, invitation, proposal, timeoutMillis, open)
            try { channel.awaitTranscript(); return channel }
            catch (failure: Throwable) {
                withContext(NonCancellable) { channel.closeAndJoin() }
                throw failure
            }
        }

        // Injected streams cannot prove TLS peer identity or hardware key custody. Tests use them.
        internal suspend fun authenticate(parent: CoroutineScope, stream: PairingByteStream, invitation: PairingInvitation,
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

        internal suspend fun connect(parent: CoroutineScope, stream: PairingByteStream, invitation: PairingInvitation,
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
