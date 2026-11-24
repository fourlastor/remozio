package dev.sebastiano.remozio.android.transport

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.remozio.phone.transport.ClientTLSKeyManager
import dev.remozio.phone.transport.DirectTCPConnector
import dev.remozio.phone.transport.PinnedTLSClient
import dev.remozio.phone.transport.TLSRecordSession
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.UUID
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidPinnedTLSClientTest {
    @Test fun platformTlsHandshakesAndExchangesBytesThroughThePinnedClient(): Unit = runBlocking {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "remozio-test-pinned-tls-client-" + UUID.randomUUID()
        try {
            // TLS signatures authorize raw P-256 signing as well as SHA-256.
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                .build()
            val pair = KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
                initialize(spec)
            }.generateKeyPair()
            val certificate = store.getCertificate(alias) as X509Certificate
            ClientTLSKeyManager(pair.private, arrayOf(certificate)).use { client ->
                exchangeWithSoftwareServer(client, certificate)
            }
        } finally {
            store.deleteEntry(alias)
        }
    }

    private suspend fun exchangeWithSoftwareServer(
        client: ClientTLSKeyManager,
        clientCertificate: X509Certificate,
    ) = coroutineScope {
        val (serverCertificate, serverKeys) = softwareServer()
        val context = SSLContext.getInstance("TLSv1.3").apply {
            init(serverKeys.keyManagers, arrayOf(trust(clientCertificate)), null)
        }
        val loopback = InetAddress.getByName("127.0.0.1")
        val protocol = "remozio-test/1"
        (context.serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket).use { listener ->
            listener.soTimeout = 5_000
            val serverExchange = async(Dispatchers.IO) {
                (listener.accept() as SSLSocket).use { socket ->
                    socket.soTimeout = 5_000
                    socket.sslParameters = socket.sslParameters.apply {
                        protocols = arrayOf("TLSv1.3")
                        applicationProtocols = arrayOf(protocol)
                        needClientAuth = true
                    }
                    socket.startHandshake()
                    assertArrayEquals(clientCertificate.encoded, socket.session.peerCertificates.single().encoded)
                    assertEquals("TLSv1.3", socket.session.protocol)
                    assertEquals(protocol, socket.applicationProtocol)
                    assertEquals(42, socket.inputStream.read())
                    socket.outputStream.write(43)
                    socket.outputStream.flush()
                }
            }
            val carrier = DirectTCPConnector().connect(this, InetSocketAddress(loopback, listener.localPort))
            val engine = PinnedTLSClient(arrayOf(client), serverCertificate.publicKey.encoded, protocol, 65_536)
            val session = TLSRecordSession(this, engine, carrier)
            try {
                withTimeout(10_000) {
                    session.awaitOpen()
                    session.send(byteArrayOf(42))
                    assertArrayEquals(byteArrayOf(43), session.receive())
                    serverExchange.await()
                }
            } finally {
                session.closeAndJoin()
            }
        }
    }

    private fun softwareServer(): Pair<X509Certificate, KeyManagerFactory> {
        val decoder = Base64.getDecoder()
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(decoder.decode(SERVER_KEY)))
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(decoder.decode(SERVER_CERTIFICATE).inputStream()) as X509Certificate
        val password = charArrayOf()
        val store = KeyStore.getInstance("PKCS12").apply {
            load(null)
            setKeyEntry("server", key, password, arrayOf(certificate))
        }
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, password) }
        return certificate to keys
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

    private companion object {
        // Disposable software identity for the local test server. Production never uses this key.
        const val SERVER_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgo5eW0P/wEHV3Sc/D9QA2GW9BwsoWCqT2GnRF88En27uhRANCAAT5YTkW95sNU1ewjfVyCsUWwCd/vcFkYo5vSacIW3x9uovzwGnoALDcmG6uU8vWrDX8F3zbPQus1DXhyIqDfl7i"
        const val SERVER_CERTIFICATE = "MIIBhzCCAS6gAwIBAgIUL9tt+ryYTmG7UBfFwZAM7MfE72UwCgYIKoZIzj0EAwIwKjEoMCYGA1UEAwwfUmVtb3ppbyBBbmRyb2lkIFRMUyB0ZXN0IHNlcnZlcjAeFw0yNjExMjQxMTM0MjZaFw0zNjExMjExMTM0MjZaMCoxKDAmBgNVBAMMH1JlbW96aW8gQW5kcm9pZCBUTFMgdGVzdCBzZXJ2ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT5YTkW95sNU1ewjfVyCsUWwCd/vcFkYo5vSacIW3x9uovzwGnoALDcmG6uU8vWrDX8F3zbPQus1DXhyIqDfl7iozIwMDAdBgNVHQ4EFgQUt7H2VdhLdz7kiqLD3asBVwR5/6swDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBsv5Eehc5lKSU/46WBjyvm81ZHOoyhrTkTOaaAAHSGbQIgEufCuyRcBxtWN5l+w3b86LXN6v/q8dczqan73sp1CDE="
    }
}
