package dev.sebastiano.remozio.android.enrollment

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.test.platform.app.InstrumentationRegistry
import dev.remozio.pairing.PairingByteStream
import dev.remozio.pairing.PairingSetupChannel
import dev.remozio.phone.transport.ApprovalCarrierRoute
import dev.remozio.phone.transport.DirectTCPConnector
import dev.remozio.phone.transport.PinnedTLSClient
import dev.remozio.phone.transport.TLSClientState
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
import dev.remozio.protocol.PairingSetupPreludeV2
import dev.sebastiano.remozio.android.transport.AndroidTlsTestFixture
import java.io.IOException
import java.net.InetSocketAddress
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.HexFormat
import javax.net.ssl.SSLException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test

class AndroidPairingMacLoopbackTest {
    private class PeerHandshakeRejected(cause: SSLException) : IOException("TLS rejected the peer handshake", cause)

    @Test
    fun rejectsWrongPinAndAlpnBeforeProposalAndCompletesValidPairing(): Unit = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("Requires the test-only Mac loopback fixture", args.containsKey("remozioMacPairingPort"))
        val port = requireNotNull(args.getString("remozioMacPairingPort")).toInt()
        require(port in 1..65535)
        val invitation = PairingInvitation.importText(requireNotNull(args.getString("remozioMacPairingInvitation")))
        val window = HexFormat.of().parseHex(requireNotNull(args.getString("remozioMacPairingWindow")))
        // These test-only bytes match the Mac fixture. No user invitation or signing identity is used.
        val credentials = PairingInvitationV2(invitation, window, ByteArray(32) { 0x63 }, lifetimeMilliseconds = 120_000u)
        val destination = InetSocketAddress("10.0.2.2", port)
        val scope = ChannelScope(invitation.macID.copyBytes(), invitation.accountID.copyBytes(),
            randomBytes(16), randomBytes(16))
        val offer = ChannelOffer(ChannelRole.PHONE, scope, randomBytes(32), setOf(1u), emptyList(), emptySet())
        val biometric = keyGenerator().generateKeyPair()
        val decision = keyGenerator().generateKeyPair()

        withLocalNetworkPermission { context ->
            withTimeout(45_000) {
                AndroidTlsTestFixture.create().use { identity ->
                    val proposal = PairingPhoneProposal(offer, PairingKey(randomBytes(16), point(identity.clientCertificate.publicKey)),
                        PairingKey(randomBytes(16), point(decision.public)), PairingKey(randomBytes(16), point(biometric.public)))
                    val serverPin = HexFormat.of().parseHex("3059301306072a8648ce3d020106082a8648ce3d030107034200") +
                        invitation.transportPublicKey.copyBytes()
                    requireLocalNetworkPermission(context)
                    requireTLSRejection(destination, invitation, proposal, identity,
                        keyGenerator().generateKeyPair().public.encoded, PairingSetupPreludeV2.APPLICATION_PROTOCOL)
                    requireLocalNetworkPermission(context)
                    requireTLSRejection(destination, invitation, proposal, identity, serverPin, PairingSetupFrame.APPLICATION_PROTOCOL)

                    requireLocalNetworkPermission(context)
                    val channel = authenticatePairingV2Routes(this, flowOf(ApprovalCarrierRoute { owner ->
                        DirectTCPConnector().connect(owner, destination)
                    }), arrayOf(identity.clientKeys), credentials, proposal, 10_000, AndroidInvitationExporter)
                    try {
                        var proposals = 0
                        val transcript = channel.awaitTranscriptV2(credentials) { proposals += 1 }
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
    }

    private suspend fun CoroutineScope.requireTLSRejection(
        destination: InetSocketAddress,
        invitation: PairingInvitation,
        proposal: PairingPhoneProposal,
        identity: AndroidTlsTestFixture,
        pin: ByteArray,
        protocol: String,
    ) {
        var plaintextBytes = 0
        try {
            val channel = PairingSetupChannel.authenticate(this, invitation, proposal, timeoutMillis = 8_000) { owner ->
                val tls = PinnedTLSClient(arrayOf(identity.clientKeys), pin, protocol, 1_048_576)
                val carrier = try {
                    DirectTCPConnector().connect(owner, destination)
                } catch (failure: Throwable) {
                    tls.close()
                    throw failure
                }
                object : PairingByteStream {
                    override suspend fun awaitOpen() {
                        var progress = tls.start()
                        while (progress.state == TLSClientState.HANDSHAKING) {
                            for (record in progress.encrypted) carrier.send(record.copyBytes())
                            val serverRecord = checkNotNull(carrier.receive()) { "Peer closed before TLS rejected its handshake" }
                            progress = try {
                                tls.receive(serverRecord)
                            } catch (failure: SSLException) {
                                assertEquals(TLSClientState.FAILED, tls.state())
                                throw PeerHandshakeRejected(failure)
                            }
                        }
                        throw AssertionError("The incompatible TLS configuration did not fail during the handshake")
                    }

                    override suspend fun send(bytes: ByteArray) {
                        plaintextBytes += bytes.size
                        throw AssertionError("Plaintext was submitted on an incompatible TLS connection")
                    }

                    override suspend fun receive(): ByteArray? =
                        throw AssertionError("Pairing attempted to read plaintext after an incompatible TLS handshake")

                    override fun close() {
                        carrier.close()
                        tls.close()
                    }

                    override suspend fun awaitClosed() = carrier.awaitClosed()
                }
            }
            channel.closeAndJoin()
            throw AssertionError("Pairing authenticated an incompatible TLS connection")
        } catch (_: PeerHandshakeRejected) {
            // A TCP error, EOF or timeout cannot reach this branch.
            assertEquals(0, plaintextBytes)
        }
    }

    private suspend fun withLocalNetworkPermission(body: suspend (Context) -> Unit) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val permission = Manifest.permission.ACCESS_LOCAL_NETWORK
        val grantedForTest = context.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED
        if (grantedForTest) instrumentation.uiAutomation.grantRuntimePermission(context.packageName, permission)
        try {
            body(context)
        } finally {
            if (grantedForTest) context.revokeSelfPermissionOnKill(permission)
        }
    }

    private fun requireLocalNetworkPermission(context: Context) {
        assertEquals("The emulator test needs local network permission", PackageManager.PERMISSION_GRANTED,
            context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK))
    }

    private fun keyGenerator() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }

    private fun point(key: PublicKey) = key.encoded.takeLast(65).toByteArray()

    private fun randomBytes(size: Int) = ByteArray(size).also(SecureRandom()::nextBytes)
}
