package dev.remozio.phone.transport

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import java.io.Closeable
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** Platform HTTPS trust for the outer relay only. The caller must still establish pinned inner TLS. */
class RelayConnector internal constructor(private val sockets: SSLSocketFactory) {
    constructor() : this(SSLSocketFactory.getDefault() as SSLSocketFactory)

    /** Uses the exact endpoint retained with the credential; callers cannot substitute a route. */
    suspend fun connect(parent: CoroutineScope, credential: RelayAccessCredential,
        requireCurrent: suspend () -> Unit = {},
    ): EncryptedRecordTransport = connect(parent, credential.endpoint, credential, requireCurrent = requireCurrent)

    suspend fun connect(
        parent: CoroutineScope,
        endpoint: RelayEndpoint,
        credential: RelayAccessCredential,
        timeoutMillis: Long = 15_000,
        maximumMessageBytes: Int = 32_768,
        queueCapacity: Int = 1,
        requireCurrent: suspend () -> Unit = {},
    ): EncryptedRecordTransport {
        require(credential.endpoint == endpoint)
        require(timeoutMillis in 1..60_000 && maximumMessageBytes in 1..32_768 && queueCapacity in 1..64)
        val parentJob = requireNotNull(parent.coroutineContext[Job])
        parentJob.ensureActive()
        val provisional = AtomicReference<SocketCarrier?>()
        try {
            val carrier = open(parentJob, endpoint, credential, timeoutMillis, maximumMessageBytes,
                queueCapacity, requireCurrent, provisional)
            currentCoroutineContext().ensureActive()
            provisional.set(null)
            return carrier
        } finally {
            withContext(NonCancellable) {
                provisional.getAndSet(null)?.let { it.close(); it.awaitClosed() }
            }
        }
    }

    private suspend fun open(parentJob: Job, endpoint: RelayEndpoint, credential: RelayAccessCredential, timeoutMillis: Long,
        maximumMessageBytes: Int, queueCapacity: Int, requireCurrent: suspend () -> Unit,
        provisional: AtomicReference<SocketCarrier?>,
    ): SocketCarrier = withTimeoutOrNull(timeoutMillis) {
        suspendCancellableCoroutine { continuation ->
            val lifetime = SocketLifetime(parentJob)
            val setup = launch(Dispatchers.IO, start = CoroutineStart.LAZY) {
                try {
                    val raw = Socket()
                    lifetime.install(raw)
                    raw.connect(InetSocketAddress(endpoint.host, endpoint.port), timeoutMillis.toInt())
                    coroutineContext.ensureActive()
                    val secure = sockets.createSocket(raw, endpoint.host, endpoint.port, true) as SSLSocket
                    lifetime.install(secure)
                    secure.soTimeout = timeoutMillis.toInt()
                    secure.enabledProtocols = secure.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
                    secure.sslParameters = secure.sslParameters.apply {
                        endpointIdentificationAlgorithm = "HTTPS"
                        serverNames = listOf(SNIHostName(endpoint.host))
                        applicationProtocols = arrayOf("http/1.1")
                    }
                    secure.startHandshake()
                    coroutineContext.ensureActive()
                    if (secure.applicationProtocol !in listOf("", "http/1.1")) throw IOException("Relay protocol rejected")
                    requireCurrent()
                    coroutineContext.ensureActive()
                    WebSocketUpgrade.exchange(secure.inputStream, secure.outputStream, endpoint, credential)
                    coroutineContext.ensureActive()
                    secure.soTimeout = 0
                    val carrier = SocketCarrier(secure, lifetime, maximumMessageBytes, queueCapacity)
                    provisional.set(carrier)
                    continuation.resume(carrier) { _, value, _ -> value.close() }
                } catch (_: Exception) {
                    continuation.resumeWith(Result.failure(IOException("Relay connection rejected")))
                    lifetime.close()
                }
            }
            val ownerCompletion = lifetime.owner.invokeOnCompletion { continuation.cancel() }
            continuation.invokeOnCancellation { lifetime.close(); setup.cancel(); ownerCompletion.dispose() }
            setup.invokeOnCompletion { ownerCompletion.dispose() }
            setup.start()
        }
    } ?: throw IOException("Relay connection timed out")
}

private class SocketLifetime(parent: Job) : AutoCloseable {
    val owner = SupervisorJob(parent)
    val scope = CoroutineScope(owner + Dispatchers.IO)
    private val lock = Any()
    private var closed = false
    private val resources = mutableListOf<Closeable>()

    init {
        // This observer only closes a socket. It does not dispatch blocking reads or provider work.
        CoroutineScope(owner + Dispatchers.Unconfined).launch(start = CoroutineStart.UNDISPATCHED) {
            try { awaitCancellation() } finally { releaseSocket() }
        }
    }
    fun install(value: Closeable) {
        val accepted = synchronized(lock) { if (closed) false else { resources.add(value); true } }
        if (!accepted) { value.close(); throw IOException("Relay connection closed") }
    }
    fun releaseSocket() {
        val values = synchronized(lock) { closed = true; resources.toList().also { resources.clear() } }
        // Close TCP before TLS so shutdown cannot wait while sending a TLS close notification.
        values.forEach { value -> runCatching { value.close() } }
    }
    override fun close() { releaseSocket(); owner.cancel() }
}

private class SocketCarrier(
    socket: SSLSocket,
    private val lifetime: SocketLifetime,
    override val maximumMessageBytes: Int,
    queueCapacity: Int,
) : EncryptedRecordTransport {
    private val closed = AtomicBoolean(false)
    private val input = ByteChannel(autoFlush = true)
    private val output = ByteChannel(autoFlush = true)
    private val framer = WebSocketRecordTransport(lifetime.scope, input, output, maximumMessageBytes, queueCapacity) { lifetime.releaseSocket() }
    private val reader = lifetime.scope.launch {
        try {
            val buffer = ByteArray(16_384)
            while (true) {
                val count = socket.inputStream.read(buffer)
                if (count < 0) break
                if (count == 0) throw IOException("Relay read made no progress")
                input.writeFully(buffer, 0, count)
            }
            input.flushAndClose()
        } catch (_: Exception) { input.cancel(IOException("Relay input closed")); lifetime.releaseSocket() }
    }
    private val writer = lifetime.scope.launch {
        try {
            val buffer = ByteArray(16_384)
            while (true) {
                val count = output.readAvailable(buffer)
                if (count < 0) break
                socket.outputStream.write(buffer, 0, count)
                socket.outputStream.flush()
            }
        } catch (_: Exception) { input.cancel(IOException("Relay output closed")); output.cancel(IOException("Relay output closed")); lifetime.releaseSocket() }
    }
    override suspend fun send(ciphertext: ByteArray) = framer.send(ciphertext)
    override suspend fun receive(): ByteArray? = framer.receive()
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            framer.close()
            lifetime.close()
        }
    }
    override suspend fun awaitClosed() { framer.awaitClosed(); reader.join(); writer.join(); lifetime.owner.join() }
}
