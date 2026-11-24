package dev.remozio.pairing

import dev.remozio.protocol.ChannelOffer
import dev.remozio.protocol.ChannelRole
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PairingInvitationV2
import dev.remozio.protocol.PairingKey
import dev.remozio.protocol.PairingPhoneProposal
import dev.remozio.protocol.PairingSetupPreludeV2
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException

interface IosPairingV2Transport : PairingTransport {
    fun takeInvitationExporter(): ByteArray?
}

interface IosPairingPreviewResult {
    fun finished(code: String?)
}

object IosPairingV2Preview {
    val applicationProtocol: String get() = PairingSetupPreludeV2.APPLICATION_PROTOCOL
    val exporterLabel: String get() = PairingInvitationV2.EXPORTER_LABEL

    fun parseInvitation(text: String): IosPairingPreviewInvitation? {
        if (text.length > 1_100) return null
        val invitation = try {
            PairingInvitationV2.importText(text.trim())
        } catch (_: IllegalArgumentException) {
            return null
        } catch (_: IllegalStateException) {
            return null
        }
        if (invitation.replacement != null) return null
        return IosPairingPreviewInvitation(invitation)
    }
}

class IosPairingPreviewInvitation internal constructor(private val invitation: PairingInvitationV2) {
    val label: String get() = invitation.invitation.label

    fun start(keys: PlatformPairingKeys, result: IosPairingPreviewResult): IosPairingPreviewAttempt =
        IosPairingPreviewAttempt { scope ->
            val code = try {
                previewPairingV2(scope, invitation, keys)
            } catch (failure: CancellationException) {
                currentCoroutineContext().ensureActive()
                null
            } catch (_: Exception) {
                null
            }
            currentCoroutineContext().ensureActive()
            result.finished(code)
        }

    override fun toString() = "IosPairingPreviewInvitation(redacted)"
}

class IosPairingPreviewAttempt internal constructor(attempt: suspend (CoroutineScope) -> Unit) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    init {
        scope.launch {
            try {
                attempt(scope)
            } finally {
                scope.cancel()
            }
        }
    }

    fun cancel() = scope.cancel()
}

internal suspend fun previewPairingV2(
    scope: CoroutineScope,
    invitation: PairingInvitationV2,
    keys: PlatformPairingKeys,
): String {
    require(invitation.replacement == null)
    val mac = invitation.invitation
    val phone = ChannelOffer(ChannelRole.PHONE,
        ChannelScope(mac.macID.copyBytes(), mac.accountID.copyBytes(), secureRandom(16), secureRandom(16)),
        secureRandom(32), setOf(1uL), emptyList(), emptySet())
    val proposal = PairingPhoneProposal(phone, PairingKey(secureRandom(16), keys.transportPublicKey.copyOf()),
        PairingKey(secureRandom(16), keys.decisionPublicKey.copyOf()),
        PairingKey(secureRandom(16), keys.biometricPublicKey.copyOf()))
    val budget = minOf(invitation.lifetimeMilliseconds.toLong(), 15_000)
    return withTimeout(budget) {
        val channel = PairingSetupChannel.authenticate(scope, mac, proposal, budget) {
            val candidate = keys.openTransport(mac.macID.copyBytes(), mac.accountID.copyBytes(),
                P256_SPKI_PREFIX + mac.transportPublicKey.copyBytes(), IosPairingV2Preview.applicationProtocol)
            val transport = candidate as? IosPairingV2Transport
            if (transport == null) {
                candidate.cancel()
                throw IOException("Pairing v2 transport unavailable")
            }
            val stream = PairingTransportStream(transport)
            object : PairingV2ByteStream, PairingByteStream by stream {
                override fun pairingExporter(): ByteArray {
                    val exporter = transport.takeInvitationExporter() ?: throw IOException("Pairing exporter unavailable")
                    if (exporter.size == 32) return exporter
                    exporter.fill(0)
                    throw IOException("Invalid pairing exporter length")
                }
            }
        }
        try {
            channel.awaitTranscriptV2(invitation).verificationCode()
        } finally {
            withContext(NonCancellable) { channel.closeAndJoin() }
        }
    }
}
