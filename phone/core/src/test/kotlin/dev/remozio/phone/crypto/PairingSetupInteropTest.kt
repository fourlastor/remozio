package dev.remozio.phone.crypto

import dev.remozio.phone.transport.*
import dev.remozio.protocol.*
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManager
import kotlinx.coroutines.*
import kotlinx.serialization.json.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Test
import kotlin.test.*

/** Real native/JVM TLS on loopback with disposable software keys. No Root, administrator consent, hardware biometric or durable enrollment. */
class PairingSetupInteropTest {
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
    private inner class Fixture : AutoCloseable {
        val phone = HeldCertificate.Builder().ecdsa256().commonName("disposable-pairing-phone").build()
        val mac = HeldCertificate.Builder().ecdsa256().commonName("disposable-pairing-mac").build()
        val biometric = key(); val decision = key()
        val directory = Files.createTempDirectory("remozio-pairing-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        private val process: Process
        val port: Int
        val invitation: PairingInvitation
        val keys: Array<KeyManager> = arrayOf(HandshakeCertificates.Builder().heldCertificate(phone).build().keyManager)
        init {
            var started: Process? = null
            try {
                val identity = directory.resolve("identity.p12")
                Files.createFile(identity, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                val password = "synthetic-only".toCharArray()
                val store = KeyStore.getInstance("PKCS12").apply {
                    load(null, password); setKeyEntry("fixture", mac.keyPair.private, password, arrayOf(mac.certificate))
                }
                Files.newOutputStream(identity).use { store.store(it, password) }
                started = ProcessBuilder(System.getProperty("remozio.test.tlsPeer"), identity.toString())
                    .redirectError(directory.resolve("stderr.log").toFile()).start()
                process = started
                process.outputStream.write(("{\"peerPublicKey\":\"" + Base64.getEncoder().encodeToString(phone.certificate.publicKey.encoded) +
                    "\",\"pairing\":true}\n").toByteArray()); process.outputStream.flush()
                val executor = Executors.newSingleThreadExecutor()
                val line = try { executor.submit<String> { process.inputStream.bufferedReader().readLine() }.get(10, TimeUnit.SECONDS) }
                finally { executor.shutdownNow() }
                val output = Json.parseToJsonElement(line).jsonObject
                port = output.getValue("port").jsonPrimitive.int
                invitation = PairingInvitation.importText(output.getValue("invitation").jsonPrimitive.content)
            } catch (failure: Throwable) {
                started?.destroyForcibly(); started?.waitFor(5, TimeUnit.SECONDS)
                directory.toFile().deleteRecursively(); throw failure
            }
        }
        fun proposal(invite: PairingInvitation = invitation, transport: KeyPair = phone.keyPair): PairingPhoneProposal {
            val offer = ChannelOffer(ChannelRole.PHONE, ChannelScope(invite.macID.copyBytes(), invite.accountID.copyBytes(),
                ByteArray(16) { 3 }, ByteArray(16) { 4 }), ByteArray(32).also(java.security.SecureRandom()::nextBytes),
                setOf(1u), emptyList(), emptySet())
            return PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 5 }, point(transport)),
                PairingKey(ByteArray(16) { 6 }, point(decision)), PairingKey(ByteArray(16) { 7 }, point(biometric)))
        }
        suspend fun open(parent: CoroutineScope): EncryptedRecordTransport = DirectTCPConnector().connect(parent,
            InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127,0,0,1)), port))
        fun proof(transcript: PairingTranscript): ByteArray = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(biometric.private); update(transcript.signingInput(PairingProofPurpose.PHONE_BIOMETRIC)); sign()
        })
        override fun close() {
            runCatching { process.outputStream.write('q'.code); process.outputStream.flush(); process.outputStream.close() }
            val drained = process.waitFor(5, TimeUnit.SECONDS)
            if (!drained) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
            directory.toFile().deleteRecursively()
            assertTrue(drained, "Native setup fixture did not drain its handlers")
            assertEquals(0, process.exitValue(), "Native setup fixture did not stop cleanly")
        }
    }
    @Test fun unpairedTLSCandidateReceivesAndVerifiesTheExactSetupReceipt(): Unit = runBlocking {
        Fixture().use { f ->
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            var channel: PairingSetupChannel? = null
            try {
                channel = withTimeout(15000) { PairingSetupChannel.connect(scope, f.open(scope), f.keys, f.invitation, f.proposal()) }
                val transcript = channel.transcript
                val receipt = withTimeout(5000) { channel.submitProof(transcript.digest(), f.proof(transcript)) }
                assertTrue(transcript.verify(receipt, f.invitation.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
                assertFails { channel.submitProof(transcript.digest(), f.proof(transcript)) }
            } finally { channel?.closeAndJoin(); owner.cancelAndJoin() }
        }
    }
    @Test fun nativeSetupRejectsATransportClaimThatDiffersFromTheTLSClient(): Unit = runBlocking {
        Fixture().use { f ->
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            try {
                rejectedWithin(10000) { PairingSetupChannel.connect(scope, f.open(scope), f.keys, f.invitation, f.proposal(transport = key())) }
            } finally { owner.cancelAndJoin() }
        }
    }
    @Test fun invitationPinAndAuthorityChangesFailBeforeABiometricProof(): Unit = runBlocking {
        Fixture().use { f ->
            for (changeAuthority in listOf(false, true)) {
                val other = point(key())
                val invitation = PairingInvitation(f.invitation.macID.copyBytes(), f.invitation.accountID.copyBytes(), "changed",
                    if (changeAuthority) other else f.invitation.authorityPublicKey.copyBytes(),
                    if (changeAuthority) f.invitation.transportPublicKey.copyBytes() else other, 1u)
                val owner = SupervisorJob(); val scope = CoroutineScope(owner)
                try { rejectedWithin(10000) { PairingSetupChannel.connect(scope, f.open(scope), f.keys, invitation, f.proposal(invitation)) } }
                finally { owner.cancelAndJoin() }
            }
        }
    }
    @Test fun approvalALPNCannotUseTheSetupListener(): Unit = runBlocking {
        Fixture().use { f ->
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            var session: TLSRecordSession? = null
            try {
                session = TLSRecordSession(scope, PinnedTLSClient(f.keys, f.mac.certificate.publicKey.encoded, "remozio/1", 1_048_576), f.open(scope))
                rejectedWithin(5000) { session.awaitOpen(); session.receive() }
            } finally { session?.closeAndJoin(); owner.cancelAndJoin() }
        }
    }
}
