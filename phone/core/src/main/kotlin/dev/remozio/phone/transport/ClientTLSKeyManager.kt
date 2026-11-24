package dev.remozio.phone.transport

import dev.remozio.protocol.P256SignatureEncoding
import dev.remozio.protocol.PairingRecoveryQuery
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager

/**
 * One P-256 client identity for one enrollment. The platform loader establishes key custody separately.
 * Closing drops this owner's references; the host must also close engines that already obtained a key.
 */
class ClientTLSKeyManager(privateKey: PrivateKey, certificateChain: Array<X509Certificate>) : X509ExtendedKeyManager(), AutoCloseable {
    private var key: PrivateKey? = privateKey
    private var certificates: Array<X509Certificate>?

    init {
        require(privateKey.algorithm == "EC") { "EC client key required" }
        require(certificateChain.size in 1..8) { "Invalid client certificate chain" }
        val factory = CertificateFactory.getInstance("X.509")
        certificates = certificateChain.map { certificate ->
            val encoded = certificate.encoded
            require(encoded.size in 1..8_192) { "Invalid client certificate size" }
            factory.generateCertificate(encoded.inputStream()) as X509Certificate
        }.toTypedArray()
        p256TransportPin(requireNotNull(certificates).first().publicKey.encoded)
    }

    @Synchronized override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? =
        if (eligible(keyType, issuers)) arrayOf(ALIAS) else null

    @Synchronized override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? =
        if (keyType?.any { eligible(it, issuers) } == true) ALIAS else null

    @Synchronized override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? =
        if (keyType?.any { eligible(it, issuers) } == true) ALIAS else null

    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
    override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?): String? = null

    @Synchronized override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
        if (alias == ALIAS && key != null) certificates?.copyOf() else null

    @Synchronized override fun getPrivateKey(alias: String?): PrivateKey? = if (alias == ALIAS) key else null

    @Synchronized internal fun signRecovery(query: PairingRecoveryQuery, exporter: ByteArray, challenge: ByteArray): ByteArray {
        val input = query.signingInput(exporter, challenge)
        return try {
            P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(checkNotNull(key))
                update(input)
                sign()
            })
        } finally {
            input.fill(0)
        }
    }

    @Synchronized override fun close() { key = null; certificates = null }

    override fun toString(): String = "ClientTLSKeyManager(redacted)"

    private fun eligible(keyType: String?, issuers: Array<out Principal>?): Boolean {
        val chain = certificates ?: return false
        if (key == null || keyType != "EC") return false
        try { chain.first().checkValidity() } catch (_: CertificateException) { return false }
        return issuers.isNullOrEmpty() || issuers.any { issuer -> chain.any { it.issuerX500Principal == issuer } }
    }

    private companion object { const val ALIAS = "remozio-client" }
}
