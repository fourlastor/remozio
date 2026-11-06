package dev.remozio.phone.crypto

import dev.remozio.pairing.PairingSetupChannel
import dev.remozio.phone.transport.*
import dev.remozio.protocol.*
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManager
import kotlinx.coroutines.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Test
import kotlin.test.*

/** The Android protocol client pairs with the real `remozio-linux-pair` binary over loopback TLS. The operator's
 * confirmation arrives on the tool's standard input as the code the phone computes. Software keys only: no
 * biometric hardware, no administrator consent and no protected host service. */
class LinuxPairToolLoopbackTest {
    private val banner = "EXPERIMENT: software keys. Not the protected host service."
    private val tool = File(checkNotNull(System.getProperty("remozio.test.linuxPairTool")) { "remozio.test.linuxPairTool is not set" })

    private fun key(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun point(pair: KeyPair): ByteArray {
        val p = (pair.public as ECPublicKey).w
        fun scalar(n: java.math.BigInteger): ByteArray = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
        return byteArrayOf(4) + scalar(p.affineX) + scalar(p.affineY)
    }
    private suspend fun rejectedWithin(timeoutMillis: Long, operation: suspend () -> Unit) {
        val failure = assertFails { withTimeout(timeoutMillis) { operation() } }
        assertFalse(failure is TimeoutCancellationException, "A timeout does not prove rejection")
    }

    private inner class Phone(val tag: Byte) {
        val transport = HeldCertificate.Builder().ecdsa256().commonName("disposable-pairing-phone").build()
        val biometric = key(); val decision = key()
        val keys: Array<KeyManager> = arrayOf(HandshakeCertificates.Builder().heldCertificate(transport).build().keyManager)
        fun proposal(invitation: PairingInvitation, transportPoint: ByteArray = point(transport.keyPair)): PairingPhoneProposal {
            val offer = ChannelOffer(ChannelRole.PHONE, ChannelScope(invitation.macID.copyBytes(), invitation.accountID.copyBytes(),
                ByteArray(16) { tag }, ByteArray(16) { 4 }), ByteArray(32).also(java.security.SecureRandom()::nextBytes),
                setOf(1u), emptyList(), emptySet())
            return PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 5 }, transportPoint),
                PairingKey(ByteArray(16) { 6 }, point(decision)), PairingKey(ByteArray(16) { 7 }, point(biometric)))
        }
        fun proof(transcript: PairingTranscript): ByteArray = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(biometric.private); update(transcript.signingInput(PairingProofPurpose.PHONE_BIOMETRIC)); sign()
        })
    }

    private inner class Fixture : AutoCloseable {
        val directory: Path = Files.createTempDirectory("remozio-linux-pair-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val state: Path = directory.resolve("state")
        val invitation: PairingInvitation
        private var pairing: Process? = null
        private val lines = LinkedBlockingQueue<String>()
        val output = mutableListOf<String>()

        init {
            try {
                val created = run("init", "--label", "loopback")
                assertEquals(0, created.first, created.second.joinToString("\n"))
                invitation = PairingInvitation.importText(created.second.single { it.startsWith("remozio-pairing:v1:") })
            } catch (failure: Throwable) { directory.toFile().deleteRecursively(); throw failure }
        }

        fun run(vararg arguments: String): Pair<Int, List<String>> {
            val process = ProcessBuilder(listOf(tool.path, "--state-dir", state.toString()) + arguments)
                .redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null"))).start()
            val text = process.inputStream.bufferedReader().readLines()
            assertTrue(process.waitFor(30, TimeUnit.SECONDS))
            assertEquals(banner, text.firstOrNull(), "every command prints the experiment banner first")
            return process.exitValue() to text
        }

        /** Starts `pair` on an ephemeral loopback port and returns the port. */
        fun startPairing(): Int {
            val process = ProcessBuilder(tool.path, "--state-dir", state.toString(), "pair", "--listen", "127.0.0.1:0")
                .redirectErrorStream(true).start()
            pairing = process
            Thread { process.inputStream.bufferedReader().forEachLine { lines.put(it) } }.apply { isDaemon = true; start() }
            val pattern = Regex("Listening on 127\\.0\\.0\\.1:(\\d+)")
            while (true) {
                val line = next(10_000)
                pattern.matchEntire(line)?.let { return it.groupValues[1].toInt() }
            }
        }

        fun next(timeoutMillis: Long): String {
            val line = checkNotNull(lines.poll(timeoutMillis, TimeUnit.MILLISECONDS)) { "pair printed nothing more; so far: $output" }
            output.add(line); return line
        }

        fun awaitLine(prefix: String): String {
            while (true) { val line = next(10_000); if (line.startsWith(prefix)) return line }
        }

        /** What the operator types after reading the phone's screen. */
        fun type(text: String) {
            val input = checkNotNull(pairing).outputStream
            input.write((text + "\n").toByteArray()); input.flush()
        }

        fun awaitExit(): Int {
            val process = checkNotNull(pairing)
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "pair did not exit; output: $output")
            while (true) { val line = lines.poll(1, TimeUnit.SECONDS) ?: break; output.add(line) }
            return process.exitValue()
        }

        suspend fun open(scope: CoroutineScope, port: Int): EncryptedRecordTransport = DirectTCPConnector().connect(scope,
            InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port))

        fun enrolledPhones(): List<String> {
            val (status, text) = run("list")
            assertEquals(0, status, text.joinToString("\n"))
            val count = text.single { it.startsWith("Enrolled phones: ") }.removePrefix("Enrolled phones: ").toInt()
            return text.filter { it.startsWith("phone ") }.also { assertEquals(count, it.size) }
        }

        override fun close() {
            pairing?.let { if (it.isAlive) { it.destroyForcibly(); it.waitFor(5, TimeUnit.SECONDS) } }
            directory.toFile().deleteRecursively()
        }
    }

    @Test fun androidClientPairsWithTheLinuxToolAndVerifiesTheReceipt(): Unit = runBlocking {
        Fixture().use { f ->
            assertEquals(emptyList(), f.enrolledPhones())
            val port = f.startPairing()
            assertEquals("Loopback address: not advertised.", f.awaitLine("Loopback"))
            val phone = Phone(3)
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            var channel: PairingSetupChannel? = null
            try {
                channel = withTimeout(15_000) {
                    PairingSetupChannel.connect(scope, f.open(scope, port), phone.keys, f.invitation, phone.proposal(f.invitation))
                }
                val transcript = channel.transcript
                f.awaitLine("Compare on the phone.")
                assertTrue(f.output.none { transcript.verificationCode() in it }, "the terminal must not show the code")
                f.type(transcript.verificationCode().lowercase())
                val receipt = withTimeout(10_000) { channel.submitProof(transcript.digest(), phone.proof(transcript)) }
                assertTrue(transcript.verify(receipt, f.invitation.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
                assertEquals(0, f.awaitExit(), f.output.joinToString("\n"))
                assertTrue(f.output.any { it.startsWith("Enrolled phone 03030303030303030303030303030303") && it.endsWith("Receipt sent.") })
                val setup = transcript.setupID.copyBytes().joinToString("") { "%02x".format(it) }
                assertEquals(listOf("phone ${"03".repeat(16)} epoch ${"04".repeat(16)} setup $setup"), f.enrolledPhones())
            } finally { channel?.closeAndJoin(); owner.cancelAndJoin() }
        }
    }

    @Test fun aWrongCodeCommitsNothingAndSendsNoReceipt(): Unit = runBlocking {
        Fixture().use { f ->
            val port = f.startPairing()
            val phone = Phone(3)
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            var channel: PairingSetupChannel? = null
            try {
                channel = withTimeout(15_000) {
                    PairingSetupChannel.connect(scope, f.open(scope, port), phone.keys, f.invitation, phone.proposal(f.invitation))
                }
                val transcript = channel.transcript
                f.awaitLine("Compare on the phone.")
                val code = transcript.verificationCode()
                f.type(code.dropLast(1) + if (code.last() == '2') '3' else '2')
                rejectedWithin(10_000) { channel.submitProof(transcript.digest(), phone.proof(transcript)) }
                assertEquals(1, f.awaitExit(), f.output.joinToString("\n"))
                assertTrue("Setup failed: codeMismatch." in f.output)
                assertEquals(emptyList(), f.enrolledPhones())
            } finally { channel?.closeAndJoin(); owner.cancelAndJoin() }
        }
    }

    @Test fun aCandidateWhoseTransportClaimDiffersFromItsTLSKeyNeverReachesTheOperator(): Unit = runBlocking {
        Fixture().use { f ->
            val port = f.startPairing()
            val impostor = Phone(9)
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            try {
                rejectedWithin(10_000) {
                    PairingSetupChannel.connect(scope, f.open(scope, port), impostor.keys, f.invitation,
                        impostor.proposal(f.invitation, transportPoint = point(key())))
                }
                assertEquals("Setup failed: wrongTransportKey.", f.awaitLine("Setup failed"))

                // The tool keeps listening, and the right phone still pairs on the same run.
                val phone = Phone(3)
                val channel = withTimeout(15_000) {
                    PairingSetupChannel.connect(scope, f.open(scope, port), phone.keys, f.invitation, phone.proposal(f.invitation))
                }
                try {
                    val transcript = channel.transcript
                    f.awaitLine("Compare on the phone.")
                    f.type(transcript.verificationCode())
                    val receipt = withTimeout(10_000) { channel.submitProof(transcript.digest(), phone.proof(transcript)) }
                    assertTrue(transcript.verify(receipt, f.invitation.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
                } finally { channel.closeAndJoin() }
                assertEquals(0, f.awaitExit(), f.output.joinToString("\n"))
                assertEquals(1, f.enrolledPhones().size)
                assertTrue(f.enrolledPhones().single().startsWith("phone ${"03".repeat(16)}"))
            } finally { owner.cancelAndJoin() }
        }
    }
}
