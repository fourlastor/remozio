package dev.sebastiano.remozio.android.transport

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.remozio.phone.transport.DirectTCPConnector
import dev.remozio.phone.transport.PinnedTLSClient
import dev.remozio.phone.transport.TLSRecordSession
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidPinnedTLSClientTest {
    @Test fun platformTlsHandshakesAndExchangesBytesThroughThePinnedClient(): Unit = runBlocking {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val serverAlias = "remozio-test-pinned-tls-server-" + UUID.randomUUID()
        val clientAlias = "remozio-test-pinned-tls-client-" + UUID.randomUUID()
        try {
            val server = identity(store, serverAlias)
            val client = identity(store, clientAlias)
            val context = SSLContext.getInstance("TLSv1.3").apply {
                init(arrayOf(server), arrayOf(trust(client.certificate)), null)
            }
            val loopback = InetAddress.getByName("127.0.0.1")
            val protocol = "remozio-test/1"
            (context.serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket).use { listener ->
                listener.soTimeout = 5_000
                listener.needClientAuth = true
                listener.enabledProtocols = arrayOf("TLSv1.3")
                listener.sslParameters = listener.sslParameters.apply { applicationProtocols = arrayOf(protocol) }
                val exchange = async(Dispatchers.IO) {
                    (listener.accept() as SSLSocket).use { socket ->
                        socket.soTimeout = 5_000
                        socket.startHandshake()
                        assertEquals("TLSv1.3", socket.session.protocol)
                        assertEquals(protocol, socket.applicationProtocol)
                        assertEquals(42, socket.inputStream.read())
                        socket.outputStream.write(43)
                        socket.outputStream.flush()
                    }
                }
                val carrier = DirectTCPConnector().connect(this, InetSocketAddress(loopback, listener.localPort))
                val engine = PinnedTLSClient(arrayOf(client), server.certificate.publicKey.encoded, protocol, 65_536)
                val session = TLSRecordSession(this, engine, carrier)
                try {
                    withTimeout(10_000) {
                        session.awaitOpen()
                        session.send(byteArrayOf(42))
                        assertArrayEquals(byteArrayOf(43), session.receive())
                        exchange.await()
                    }
                } finally {
                    session.closeAndJoin()
                }
            }
        } finally {
            store.deleteEntry(clientAlias)
            store.deleteEntry(serverAlias)
        }
    }

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
                throw CertificateException("Unexpected test certificate")
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
