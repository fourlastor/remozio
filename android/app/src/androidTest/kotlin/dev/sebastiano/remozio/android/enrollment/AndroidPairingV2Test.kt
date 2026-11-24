package dev.sebastiano.remozio.android.enrollment

import android.os.Parcelable
import android.net.ssl.SSLSockets
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.SparseArray
import android.view.View
import android.view.inputmethod.EditorInfo
import androidx.test.platform.app.InstrumentationRegistry
import dev.remozio.phone.transport.ApprovalCarrierRoute
import dev.remozio.phone.transport.DirectTCPConnector
import dev.remozio.phone.transport.PairingV2TLSProvider
import dev.remozio.phone.transport.authenticatePairingV2Routes
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.ChannelOffer
import dev.remozio.protocol.ChannelRole
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PairingInvitation
import dev.remozio.protocol.PairingInvitationV2
import dev.remozio.protocol.PairingKey
import dev.remozio.protocol.PairingPhoneProposal
import dev.remozio.protocol.PairingSetupFrame
import dev.remozio.protocol.PairingSetupPreludeV2
import dev.remozio.protocol.PairingTranscript
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class AndroidPairingV2Test {
    @Test fun editorClearsParsedInvitationsAndNeverSavesCredentialText() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.runOnMainSync {
            var invitation: PairingInvitationV2? = null
            val source = invitation(publicKey(), publicKey())
            val context = instrumentation.targetContext
            val editor = PairingInvitationV2Editor(context) { invitation = it }.apply { id = View.generateViewId() }
            assertFalse(editor.isSaveEnabled)
            assertFalse(editor.isSaveFromParentEnabled)
            assertTrue(editor.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
            editor.setText(source.exportText().dropLast(5))
            val state = SparseArray<Parcelable>()
            editor.saveHierarchyState(state)
            assertEquals(0, state.size())
            val recreated = PairingInvitationV2Editor(context) { invitation = it }.apply { id = editor.id }
            recreated.restoreHierarchyState(state)
            assertTrue(recreated.text.isEmpty())
            editor.setText(source.exportText())
            assertNotNull(invitation)
            assertEquals(source.windowID, invitation?.windowID)
            assertTrue(editor.text.isEmpty())
            editor.setText(source.exportText().padEnd(1100, 'A'))
            assertNull(invitation)
            assertTrue(editor.text.isEmpty())
        }
    }

    @Test fun v2UsesTheAndroidEngineExporterAndSeparatesTheRecoveryDomain(): Unit = runBlocking {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val serverAlias = "remozio-test-v2-server-" + UUID.randomUUID()
        val clientAlias = "remozio-test-v2-client-" + UUID.randomUUID()
        try {
            val server = identity(store, serverAlias)
            val client = identity(store, clientAlias)
            val authority = publicKey()
            val credentials = invitation(authority, server.certificate.publicKey)
            val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
            val offer = ChannelOffer(ChannelRole.PHONE, scope, ByteArray(32) { 14 }, setOf(1u), emptyList(), emptySet())
            val proposal = PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 5 }, raw(client.certificate.publicKey)),
                PairingKey(ByteArray(16) { 6 }, raw(publicKey())), PairingKey(ByteArray(16) { 7 }, raw(publicKey())))
            val transcript = PairingTranscript(ByteArray(16) { 8 }, ByteArray(32) { 9 }, offer,
                ChannelOffer(ChannelRole.MAC, scope, ByteArray(32) { 10 }, setOf(1u), emptyList(), emptySet()), 1u, 1u,
                raw(authority), raw(server.certificate.publicKey), proposal.transportKey, proposal.decisionKey,
                proposal.biometricKey, ByteArray(32) { 11 }, null, ByteArray(16) { 12 }, 1000u, 2000u)
            val context = SSLContext.getInstance("TLSv1.3").apply {
                init(arrayOf(server), arrayOf(trust(client.certificate)), null)
            }
            val address = InetAddress.getByName("127.0.0.1")
            (context.serverSocketFactory.createServerSocket(0, 1, address) as SSLServerSocket).use { listener ->
                listener.soTimeout = 5_000
                listener.needClientAuth = true
                listener.sslParameters = listener.sslParameters.apply {
                    applicationProtocols = arrayOf(PairingSetupPreludeV2.APPLICATION_PROTOCOL)
                }
                val challenge = ByteArray(32) { 13 }
                val invitationExporter = AtomicReference<ByteArray?>()
                val peer = async(Dispatchers.IO) {
                    (listener.accept() as SSLSocket).use { socket ->
                        socket.soTimeout = 5_000
                        socket.startHandshake()
                        assertEquals(PairingSetupPreludeV2.APPLICATION_PROTOCOL, socket.applicationProtocol)
                        val output = DataOutputStream(socket.outputStream)
                        fun send(body: ByteArray) { output.writeInt(body.size); output.write(body); output.flush() }
                        send(PairingSetupPreludeV2.Challenge(challenge).encode())
                        val input = DataInputStream(socket.inputStream)
                        val size = input.readInt()
                        require(size in 1..PairingSetupPreludeV2.MAXIMUM_BYTES)
                        val proof = PairingSetupPreludeV2.decode(ByteArray(size).also(input::readFully)) as PairingSetupPreludeV2.Proposal
                        val serverExporter = checkNotNull(
                            SSLSockets.exportKeyingMaterial(socket, PairingInvitationV2.EXPORTER_LABEL, ByteArray(0), 32)
                        )
                        try {
                            assertArrayEquals(proposal.encode(), proof.value.encode())
                            assertEquals(CborValue.Bytes(credentials.proof(proposal, challenge, serverExporter)), proof.tag)
                            send(PairingSetupFrame.Transcript(transcript).encode())
                            assertTrue(serverExporter.contentEquals(checkNotNull(invitationExporter.get())))
                        } finally {
                            serverExporter.fill(0)
                        }
                    }
                }
                val provider = object : PairingV2TLSProvider by AndroidInvitationExporter {
                    override fun export(engine: SSLEngine): ByteArray {
                        val v2 = checkNotNull(AndroidInvitationExporter.export(engine))
                        val recovery = checkNotNull(AndroidRecoveryExporter.export(engine))
                        try {
                            assertEquals(32, v2.size)
                            assertEquals(32, recovery.size)
                            assertFalse(v2.contentEquals(recovery))
                            invitationExporter.set(v2.copyOf())
                            return v2
                        } finally {
                            recovery.fill(0)
                        }
                    }
                }
                val channel = authenticatePairingV2Routes(this, flowOf(ApprovalCarrierRoute { owner ->
                    DirectTCPConnector().connect(owner, InetSocketAddress(address, listener.localPort))
                }), arrayOf(client), credentials, proposal, 10_000, provider)
                try {
                    assertNull(invitationExporter.get())
                    assertArrayEquals(transcript.encode(), channel.awaitTranscriptV2(credentials).encode())
                    peer.await()
                } finally {
                    channel.closeAndJoin()
                    invitationExporter.getAndSet(null)?.fill(0)
                }
            }
        } finally {
            store.deleteEntry(clientAlias)
            store.deleteEntry(serverAlias)
        }
    }

    private fun invitation(authority: PublicKey, server: PublicKey) = PairingInvitationV2(
        PairingInvitation(ByteArray(16) { 1 }, ByteArray(16) { 2 }, "Test Mac", raw(authority), raw(server), 1u),
        ByteArray(16) { 16 }, ByteArray(32) { 17 }, lifetimeMilliseconds = 60_000u,
    )

    private fun publicKey(): PublicKey = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair().public

    private fun raw(key: PublicKey) = key.encoded.takeLast(65).toByteArray()

    private fun identity(store: KeyStore, alias: String): Identity {
        KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build())
        }.generateKeyPair()
        return Identity(alias, store.getKey(alias, null) as PrivateKey, store.getCertificate(alias) as X509Certificate)
    }

    private fun trust(peer: X509Certificate) = object : X509TrustManager {
        override fun getAcceptedIssuers() = arrayOf(peer)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            if (chain.size != 1 || !chain[0].encoded.contentEquals(peer.encoded)) {
                throw java.security.cert.CertificateException("Unexpected test certificate")
            }
        }
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = checkClientTrusted(chain, authType)
    }

    private class Identity(val alias: String, val key: PrivateKey, val certificate: X509Certificate) : X509ExtendedKeyManager() {
        override fun chooseEngineClientAlias(types: Array<String>?, issuers: Array<Principal>?, engine: SSLEngine?) = alias
        override fun chooseClientAlias(types: Array<String>?, issuers: Array<Principal>?, socket: Socket?) = alias
        override fun chooseServerAlias(type: String?, issuers: Array<Principal>?, socket: Socket?) = alias
        override fun getClientAliases(type: String?, issuers: Array<Principal>?) = arrayOf(alias)
        override fun getServerAliases(type: String?, issuers: Array<Principal>?) = arrayOf(alias)
        override fun getCertificateChain(alias: String?) = if (alias == this.alias) arrayOf(certificate) else null
        override fun getPrivateKey(alias: String?) = if (alias == this.alias) key else null
    }
}
