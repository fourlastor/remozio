package dev.sebastiano.remozio.android.enrollment

import androidx.test.platform.app.InstrumentationRegistry
import dev.remozio.phone.transport.ApprovalCarrierRoute
import dev.remozio.phone.transport.DirectTCPConnector
import dev.remozio.phone.transport.PairingV2TLSProvider
import dev.remozio.phone.transport.authenticatePairingV2Routes
import dev.remozio.protocol.ChannelOffer
import dev.remozio.protocol.ChannelRole
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.P256SignatureEncoding
import dev.remozio.protocol.PairingInvitation
import dev.remozio.protocol.PairingInvitationV2
import dev.remozio.protocol.PairingKey
import dev.remozio.protocol.PairingPhoneProposal
import dev.remozio.protocol.PairingProofPurpose
import dev.remozio.protocol.PairingSetupFrame
import dev.sebastiano.remozio.android.transport.AndroidTlsTestFixture
import java.io.IOException
import java.net.InetSocketAddress
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.HexFormat
import javax.net.ssl.SSLEngine
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test

class AndroidPairingMacLoopbackTest {
    @Test
    fun rejectsWrongPinAndAlpnBeforeProposalAndCompletesValidPairing(): Unit = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("Requires the test-only Mac loopback fixture", args.containsKey("remozioMacPairingPort"))
        val port = requireNotNull(args.getString("remozioMacPairingPort")).toInt()
        require(port in 1..65535)
        val invitation = PairingInvitation.importText(requireNotNull(args.getString("remozioMacPairingInvitation")))
        val window = HexFormat.of().parseHex(requireNotNull(args.getString("remozioMacPairingWindow")))
        // These test-only bytes match the Mac fixture. No user invitation or signing identity is used.
        fun credentials(publicInvitation: PairingInvitation) =
            PairingInvitationV2(publicInvitation, window, ByteArray(32) { 0x63 }, lifetimeMilliseconds = 120_000u)

        val wrongPin = PairingInvitation(invitation.macID.copyBytes(), invitation.accountID.copyBytes(),
            invitation.label, invitation.authorityPublicKey.copyBytes(), point(keyGenerator().generateKeyPair().public),
            invitation.minimumEnvelopeVersion)
        val wrongAlpn = object : PairingV2TLSProvider by AndroidInvitationExporter {
            override fun configure(engine: SSLEngine) {
                AndroidInvitationExporter.configure(engine)
                engine.sslParameters = engine.sslParameters.apply {
                    applicationProtocols = arrayOf(PairingSetupFrame.APPLICATION_PROTOCOL)
                }
            }
        }
        val destination = InetSocketAddress("10.0.2.2", port)
        val scope = ChannelScope(invitation.macID.copyBytes(), invitation.accountID.copyBytes(),
            randomBytes(16), randomBytes(16))
        val offer = ChannelOffer(ChannelRole.PHONE, scope, randomBytes(32), setOf(1u), emptyList(), emptySet())
        val biometric = keyGenerator().generateKeyPair()
        val decision = keyGenerator().generateKeyPair()
        withTimeout(45_000) {
            AndroidTlsTestFixture.create().use { identity ->
                val proposal = PairingPhoneProposal(offer, PairingKey(randomBytes(16), point(identity.clientCertificate.publicKey)),
                    PairingKey(randomBytes(16), point(decision.public)), PairingKey(randomBytes(16), point(biometric.public)))
                suspend fun open(credentials: PairingInvitationV2, provider: PairingV2TLSProvider) =
                    authenticatePairingV2Routes(this, flowOf(ApprovalCarrierRoute { owner ->
                        DirectTCPConnector().connect(owner, destination)
                    }), arrayOf(identity.clientKeys), credentials, proposal, 10_000, provider)

                var proposals = 0
                suspend fun requireRejection(credentials: PairingInvitationV2, provider: PairingV2TLSProvider) {
                    try {
                        val channel = open(credentials, provider)
                        try {
                            channel.awaitTranscriptV2(credentials) { proposals += 1 }
                            fail("An invalid TLS configuration reached the proposal")
                        } finally {
                            channel.closeAndJoin()
                        }
                    } catch (failure: IOException) {
                        assertEquals("No authenticated pairing route", failure.message)
                    }
                    // The callback immediately precedes the sole write of the Proposal frame.
                    assertEquals(0, proposals)
                }

                requireRejection(credentials(wrongPin), AndroidInvitationExporter)
                val valid = credentials(invitation)
                requireRejection(valid, wrongAlpn)
                val channel = open(valid, AndroidInvitationExporter)
                try {
                    val transcript = channel.awaitTranscriptV2(valid) { proposals += 1 }
                    val biometricProof = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                        initSign(biometric.private)
                        update(transcript.signingInput(PairingProofPurpose.PHONE_BIOMETRIC))
                        sign()
                    })
                    val receipt = channel.submitProof(transcript.digest(), biometricProof)
                    assertEquals(64, receipt.size)
                    assertEquals(1, proposals)
                } finally {
                    channel.closeAndJoin()
                }
            }
        }
    }

    private fun keyGenerator() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }

    private fun point(key: PublicKey) = key.encoded.takeLast(65).toByteArray()

    private fun randomBytes(size: Int) = ByteArray(size).also(SecureRandom()::nextBytes)
}
