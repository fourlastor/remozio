package dev.sebastiano.remozio.android.transport

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.remozio.phone.transport.ClientTLSKeyManager
import java.net.InetAddress
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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals

internal class AndroidTlsTestFixture private constructor(
    private val store: KeyStore,
    private val alias: String,
    val clientKeys: ClientTLSKeyManager,
    val clientCertificate: X509Certificate,
    val serverCertificate: X509Certificate,
    private val server: SSLContext,
) : AutoCloseable {
    fun listen(address: InetAddress): SSLServerSocket =
        (server.serverSocketFactory.createServerSocket(0, 1, address) as SSLServerSocket).apply { soTimeout = 5_000 }

    fun handshake(socket: SSLSocket, protocol: String) {
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
    }

    override fun close() {
        try {
            clientKeys.close()
        } finally {
            store.deleteEntry(alias)
        }
    }

    companion object {
        fun create(): AndroidTlsTestFixture {
            val (serverCertificate, serverKeys) = softwareServer()
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = "remozio-test-tls-client-" + UUID.randomUUID()
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                // TLS 1.3 signs the provider's digest with the AndroidKeyStore key.
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                .build()
            var clientKeys: ClientTLSKeyManager? = null
            try {
                val pair = KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
                    initialize(spec)
                }.generateKeyPair()
                val clientCertificate = store.getCertificate(alias) as X509Certificate
                val keys = ClientTLSKeyManager(pair.private, arrayOf(clientCertificate))
                clientKeys = keys
                val context = SSLContext.getInstance("TLSv1.3").apply {
                    init(serverKeys.keyManagers, arrayOf(trust(clientCertificate)), null)
                }
                return AndroidTlsTestFixture(store, alias, keys, clientCertificate, serverCertificate, context)
            } catch (failure: Exception) {
                try {
                    clientKeys?.close()
                } finally {
                    store.deleteEntry(alias)
                }
                throw failure
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

        // Disposable software identity for the local test server. Production never uses this key.
        const val SERVER_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgo5eW0P/wEHV3Sc/D9QA2GW9BwsoWCqT2GnRF88En27uhRANCAAT5YTkW95sNU1ewjfVyCsUWwCd/vcFkYo5vSacIW3x9uovzwGnoALDcmG6uU8vWrDX8F3zbPQus1DXhyIqDfl7i"
        const val SERVER_CERTIFICATE = "MIIBhzCCAS6gAwIBAgIUL9tt+ryYTmG7UBfFwZAM7MfE72UwCgYIKoZIzj0EAwIwKjEoMCYGA1UEAwwfUmVtb3ppbyBBbmRyb2lkIFRMUyB0ZXN0IHNlcnZlcjAeFw0yNjExMjQxMTM0MjZaFw0zNjExMjExMTM0MjZaMCoxKDAmBgNVBAMMH1JlbW96aW8gQW5kcm9pZCBUTFMgdGVzdCBzZXJ2ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT5YTkW95sNU1ewjfVyCsUWwCd/vcFkYo5vSacIW3x9uovzwGnoALDcmG6uU8vWrDX8F3zbPQus1DXhyIqDfl7iozIwMDAdBgNVHQ4EFgQUt7H2VdhLdz7kiqLD3asBVwR5/6swDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBsv5Eehc5lKSU/46WBjyvm81ZHOoyhrTkTOaaAAHSGbQIgEufCuyRcBxtWN5l+w3b86LXN6v/q8dczqan73sp1CDE="
    }
}
