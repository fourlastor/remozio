package dev.remozio.pairing

import dev.remozio.protocol.*
import kotlinx.coroutines.CoroutineScope

/**
 * The platform half of one setup attempt: three fresh P-256 keys that exist only in memory, and transports that
 * present the first of them as the TLS client key. One object owns the keys, so the proposal and the TLS identity
 * always carry the same transport key.
 */
interface PlatformPairingKeys {
    /** 65-byte uncompressed points. The three are distinct. */
    val transportPublicKey: ByteArray
    val decisionPublicKey: ByteArray
    val biometricPublicKey: ByteArray

    /**
     * A transport that presents [transportPublicKey] as its client certificate key, offers exactly
     * [applicationProtocol], and accepts only a server whose leaf SPKI equals [pin]. [macID] and [accountID] select
     * the advertised service. See [PairingTransport] for the rest of the contract.
     */
    fun openTransport(macID: ByteArray, accountID: ByteArray, pin: ByteArray, applicationProtocol: String): PairingTransport
}

/** The fixed DER prefix of a P-256 SubjectPublicKeyInfo. The pin is this prefix and the 65-byte point. */
val P256_SPKI_PREFIX: ByteArray get() = byteArrayOf(0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48,
    0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00)

/**
 * Proposes the platform keys to the invited computer and returns the channel with the transcript staged.
 * Nothing is persisted and no proof is sent. The caller shows `channel.transcript.verificationCode()` and closes the
 * channel. The phone offers no request contracts yet.
 */
suspend fun PairingSetupChannel.Companion.connectPlatform(parent: CoroutineScope, invitation: PairingInvitation,
    keys: PlatformPairingKeys, timeoutMillis: Long = 300_000,
): PairingSetupChannel {
    val offer = ChannelOffer(ChannelRole.PHONE,
        ChannelScope(invitation.macID.copyBytes(), invitation.accountID.copyBytes(), secureRandom(16), secureRandom(16)),
        secureRandom(32), setOf(1uL), emptyList(), emptySet())
    val proposal = PairingPhoneProposal(offer, PairingKey(secureRandom(16), keys.transportPublicKey.copyOf()),
        PairingKey(secureRandom(16), keys.decisionPublicKey.copyOf()), PairingKey(secureRandom(16), keys.biometricPublicKey.copyOf()))
    val pin = P256_SPKI_PREFIX + invitation.transportPublicKey.copyBytes()
    return connect(parent, invitation, proposal, timeoutMillis) {
        PairingTransportStream(keys.openTransport(invitation.macID.copyBytes(), invitation.accountID.copyBytes(), pin,
            PairingSetupFrame.APPLICATION_PROTOCOL))
    }
}
