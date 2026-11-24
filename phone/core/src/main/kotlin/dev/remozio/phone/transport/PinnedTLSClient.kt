package dev.remozio.phone.transport

import dev.remozio.protocol.CborValue
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Collections
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException
import javax.net.ssl.TrustManager
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager

/** Channel state only. OPEN grants no request or decision authority. */
enum class TLSClientState { NEW, HANDSHAKING, OPEN, PEER_CLOSED, CLOSED, FAILED }

/** Consume encrypted output in order before releasing this batch. Payloads are never included in diagnostics. */
class TLSClientProgress internal constructor(
    val state: TLSClientState, val consumedPlaintextBytes: Int, encrypted: List<CborValue.Bytes>, plaintext: List<CborValue.Bytes>,
) {
    val encrypted: List<CborValue.Bytes> = Collections.unmodifiableList(ArrayList(encrypted))
    val plaintext: List<CborValue.Bytes> = Collections.unmodifiableList(ArrayList(plaintext))
    override fun toString(): String = "TLSClientProgress($state, redacted)"
}

/**
 * A transport-independent TLS 1.3 client. Trusted enrollment supplies the peer key and local key manager.
 * The host owns ordered byte delivery, deadlines, enrollment invalidation, and output backpressure.
 * Calls serialize engine work but never wait for network input. Run delegated key tasks off the UI thread.
 */
class PinnedTLSClient private constructor(
    localKeys: Array<KeyManager>, peerSubjectPublicKeyInfo: ByteArray,
    private val applicationProtocol: String, private val maximumHandshakeBytes: Int,
    private val exporterProvider: PairingTLSExporter?,
) : AutoCloseable {
    constructor(localKeys: Array<KeyManager>, peerSubjectPublicKeyInfo: ByteArray, applicationProtocol: String,
        maximumHandshakeBytes: Int,
    ) : this(localKeys, peerSubjectPublicKeyInfo, applicationProtocol, maximumHandshakeBytes, null)

    private var engine: SSLEngine?
    private val incoming = ByteBuffer.allocate(BUFFER_BYTES)
    private val outgoing = ByteBuffer.allocate(BUFFER_BYTES)
    private val decoded = ByteBuffer.allocate(BUFFER_BYTES)
    private var handshakeBytes = 0
    private var authenticated = false
    private var currentState = TLSClientState.NEW

    init {
        require(localKeys.size == 1 && localKeys[0] is X509KeyManager) { "One enrollment key manager required" }
        require(applicationProtocol.length in 1..255 && applicationProtocol.all { it.code in 0x21..0x7e })
        require(maximumHandshakeBytes in 1..1_048_576)
        val pin = p256TransportPin(peerSubjectPublicKeyInfo)
        val trust = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) { throw CertificateException("Client role only") }
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty() || !MessageDigest.isEqual(pin, chain[0].publicKey.encoded)) throw CertificateException("Wrong transport key")
                chain[0].checkValidity()
            }
        }
        // A fresh context prevents sessions from another enrollment or prior connection from being resumed.
        val context = SSLContext.getInstance("TLSv1.3")
        context.init(localKeys.copyOf(), arrayOf<TrustManager>(trust), null)
        engine = context.createSSLEngine().apply {
            useClientMode = true
            enabledProtocols = arrayOf("TLSv1.3")
            sslParameters = sslParameters.apply { applicationProtocols = arrayOf(this@PinnedTLSClient.applicationProtocol) }
            exporterProvider?.configure(this)
        }
    }

    @Synchronized internal fun pairingExporter(): ByteArray {
        check(currentState == TLSClientState.OPEN && authenticated)
        val bytes = checkNotNull(exporterProvider).export(checkNotNull(engine))
        if (bytes == null || bytes.size != 32) throw SSLException("Pairing exporter unavailable")
        return bytes
    }

    @Synchronized fun state(): TLSClientState = currentState

    @Synchronized fun start(): TLSClientProgress {
        check(currentState == TLSClientState.NEW)
        return guarded {
            currentState = TLSClientState.HANDSHAKING
            requireNotNull(engine).beginHandshake()
            pump()
        }
    }

    /** Ciphertext chunks are bounded independently of the total application message size. */
    @Synchronized fun receive(bytes: ByteArray): TLSClientProgress {
        check(currentState == TLSClientState.HANDSHAKING || currentState == TLSClientState.OPEN)
        return guarded {
            if (bytes.size > MAX_CHUNK_BYTES || bytes.size > incoming.remaining()) throw SSLException("TLS input limit")
            incoming.put(bytes)
            pump()
        }
    }

    /**
     * The host splits larger frames into chunks and retains any unconsumed suffix until peer input arrives.
     * consumedPlaintextBytes reports only the bytes accepted by this call, never delivery or execution.
     */
    @Synchronized fun send(bytes: ByteArray): TLSClientProgress {
        check(currentState == TLSClientState.OPEN)
        require(bytes.size <= MAX_CHUNK_BYTES) { "Split plaintext into bounded chunks" }
        return guarded { pump(ByteBuffer.wrap(bytes.copyOf())) }
    }

    /** An abrupt carrier EOF is a failed channel, not proof of any request outcome. */
    @Synchronized fun endOfInput(): TLSClientProgress {
        if (currentState == TLSClientState.PEER_CLOSED) return progress()
        check(currentState == TLSClientState.HANDSHAKING || currentState == TLSClientState.OPEN)
        return guarded { throw SSLException("TLS carrier ended without close notification") }
    }

    /** Abort this incarnation and release references. The host must also close its carrier and discard queued batches. */
    @Synchronized override fun close() {
        currentState = TLSClientState.CLOSED
        discard()
    }

    private fun pump(source: ByteBuffer = ByteBuffer.allocate(0)): TLSClientProgress {
        val tls = requireNotNull(engine)
        val encrypted = mutableListOf<CborValue.Bytes>()
        val plaintext = mutableListOf<CborValue.Bytes>()
        while (true) {
            val status = tls.handshakeStatus
            if (status == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                var ran = false
                while (true) { val task = tls.delegatedTask ?: break; ran = true; task.run() }
                if (!ran && tls.handshakeStatus == status) throw SSLException("TLS task made no progress")
                continue
            }
            if (!authenticated && status == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) authenticate(tls)
            val wrap = status == SSLEngineResult.HandshakeStatus.NEED_WRAP ||
                (status == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING && source.hasRemaining())
            // Some Android TLS runtimes omit this enum value even when the SDK exposes it.
            val unwrapAgain = status.name == "NEED_UNWRAP_AGAIN"
            if (!wrap && incoming.position() == 0 && !unwrapAgain) break
            outgoing.clear(); decoded.clear()
            val result = if (wrap) tls.wrap(if (authenticated) source else ByteBuffer.allocate(0), outgoing) else {
                incoming.flip()
                try { tls.unwrap(incoming, decoded) } finally { incoming.compact() }
            }
            if (!wrap) countHandshake(result.bytesConsumed())
            if (outgoing.position() > 0) {
                countHandshake(outgoing.position())
                encrypted += bytes(outgoing)
            }
            if (result.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) authenticate(tls)
            if (decoded.position() > 0) {
                if (!authenticated) throw SSLException("Plaintext before authentication")
                plaintext += bytes(decoded)
            }
            when (result.status) {
                SSLEngineResult.Status.BUFFER_OVERFLOW -> throw SSLException("TLS buffer limit")
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    if (wrap || incoming.position() == incoming.capacity()) throw SSLException("Invalid TLS underflow")
                    break
                }
                SSLEngineResult.Status.CLOSED -> {
                    if (!authenticated) throw SSLException("TLS closed before authentication")
                    currentState = TLSClientState.PEER_CLOSED
                    discard()
                    break
                }
                SSLEngineResult.Status.OK -> {
                    if (result.bytesConsumed() == 0 && result.bytesProduced() == 0 && tls.handshakeStatus == status) {
                        throw SSLException("TLS engine made no progress")
                    }
                }
            }
        }
        return TLSClientProgress(currentState, source.position(), encrypted, plaintext)
    }

    private fun authenticate(tls: SSLEngine) {
        if (tls.session.protocol != "TLSv1.3" || tls.applicationProtocol != applicationProtocol || tls.session.localCertificates.isNullOrEmpty()) {
            throw SSLException("TLS profile mismatch")
        }
        authenticated = true
        currentState = TLSClientState.OPEN
    }

    private fun countHandshake(count: Int) {
        if (!authenticated) {
            if (count > maximumHandshakeBytes - handshakeBytes) throw SSLException("TLS handshake limit")
            handshakeBytes += count
        }
    }
    private fun bytes(buffer: ByteBuffer): CborValue.Bytes {
        buffer.flip()
        return CborValue.Bytes(ByteArray(buffer.remaining()).also { buffer.get(it) })
    }
    private inline fun guarded(block: () -> TLSClientProgress): TLSClientProgress = try { block() } catch (_: Exception) {
        currentState = TLSClientState.FAILED
        discard()
        throw SSLException("TLS channel rejected")
    }
    private fun discard() {
        engine = null
        incoming.array().fill(0); outgoing.array().fill(0); decoded.array().fill(0)
        incoming.clear(); outgoing.clear(); decoded.clear()
    }
    private fun progress() = TLSClientProgress(currentState, 0, emptyList(), emptyList())

    companion object {
        private const val BUFFER_BYTES = 65_536
        private const val MAX_CHUNK_BYTES = 32_768

        internal fun forPairingV2(keys: Array<KeyManager>, pin: ByteArray, provider: PairingV2TLSProvider) =
            PinnedTLSClient(keys, pin, dev.remozio.protocol.PairingSetupPreludeV2.APPLICATION_PROTOCOL, 1_048_576, provider)

        internal fun forPairingRecovery(keys: Array<KeyManager>, pin: ByteArray,
            provider: PairingRecoveryTLSProvider,
        ) = PinnedTLSClient(keys, pin, dev.remozio.protocol.PairingRecoveryFrame.APPLICATION_PROTOCOL, 1_048_576, provider)
    }
}
