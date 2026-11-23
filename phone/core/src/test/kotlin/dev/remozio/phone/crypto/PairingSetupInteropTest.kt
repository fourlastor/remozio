package dev.remozio.phone.crypto

import dev.remozio.pairing.PairingSetupChannel
import dev.remozio.phone.enrollment.*
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
import javax.crypto.KeyGenerator
import javax.net.ssl.KeyManager
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.flowOf
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
    private inner class Fixture(private val holdPairingStage: Boolean = false, rePair: Boolean = false, dropRePairReceipt: Boolean = false) : AutoCloseable {
        val phone = HeldCertificate.Builder().ecdsa256().commonName("disposable-pairing-phone").build()
        val mac = HeldCertificate.Builder().ecdsa256().commonName("disposable-pairing-mac").build()
        val biometric = key(); val decision = key()
        val directory = Files.createTempDirectory("remozio-pairing-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        private val process: Process
        val port: Int
        val receiptPort: Int?
        val invitation: PairingInvitation
        val rePairInvitation: RePairInvitation?
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
                val arguments = buildJsonObject {
                    put("peerPublicKey", Base64.getEncoder().encodeToString(phone.certificate.publicKey.encoded))
                    put("pairing", true)
                    put("holdPairingStage", holdPairingStage)
                    put("rePair", rePair)
                    put("dropRePairReceipt", dropRePairReceipt)
                }
                process.outputStream.write((arguments.toString() + "\n").encodeToByteArray())
                process.outputStream.flush()
                val executor = Executors.newSingleThreadExecutor()
                val output = try {
                    executor.submit<Map<String, JsonElement>> {
                        val reader = process.inputStream.bufferedReader()
                        buildMap {
                            repeat(if (dropRePairReceipt) 2 else 1) {
                                putAll(Json.parseToJsonElement(reader.readLine()).jsonObject)
                            }
                        }
                    }.get(10, TimeUnit.SECONDS)
                } finally { executor.shutdownNow() }
                receiptPort = output["receiptPort"]?.jsonPrimitive?.int
                port = output.getValue("port").jsonPrimitive.int
                val text = output.getValue("invitation").jsonPrimitive.content
                rePairInvitation = if (rePair) RePairInvitation.importText(text) else null
                invitation = rePairInvitation?.invitation ?: PairingInvitation.importText(text)
            } catch (failure: Throwable) {
                started?.destroyForcibly(); started?.waitFor(5, TimeUnit.SECONDS)
                directory.toFile().deleteRecursively(); throw failure
            }
        }
        fun proposal(invite: PairingInvitation = invitation, transport: KeyPair = phone.keyPair,
                     replacement: PairingReplacement? = null): PairingPhoneProposal {
            val offer = ChannelOffer(ChannelRole.PHONE, ChannelScope(invite.macID.copyBytes(), invite.accountID.copyBytes(),
                ByteArray(16) { 3 }, ByteArray(16) { 4 }), ByteArray(32).also(java.security.SecureRandom()::nextBytes),
                setOf(1u), emptyList(), emptySet())
            return PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 5 }, point(transport)),
                PairingKey(ByteArray(16) { 6 }, point(decision)), PairingKey(ByteArray(16) { 7 }, point(biometric)), replacement)
        }
        suspend fun open(parent: CoroutineScope, destination: Int = port): EncryptedRecordTransport = DirectTCPConnector().connect(parent,
            InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127,0,0,1)), destination))
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
    // The synthetic peer checks the transmitted bytes and the client imports the invitation.
    @Test fun rePairClientImportsTheInvitationAndSendsTheSelectedPredecessorToTheSyntheticPeer(): Unit = runBlocking {
        Fixture(rePair = true).use { f ->
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            var channel: PairingSetupChannel? = null
            try {
                val replacement = checkNotNull(f.rePairInvitation).predecessor
                val wrong = PairingReplacement(replacement.phoneID.copyBytes(), ByteArray(16) { 11 })
                for (proposal in listOf(f.proposal(), f.proposal(replacement = wrong))) {
                    rejectedWithin(10000) {
                        PairingSetupChannel.connect(scope, f.open(scope), f.keys, f.invitation, proposal).closeAndJoin()
                    }
                }
                channel = withTimeout(15000) {
                    PairingSetupChannel.connect(scope, f.open(scope), f.keys, f.invitation, f.proposal(replacement = replacement))
                }
                val transcript = channel.transcript
                assertEquals(replacement.phoneID, transcript.replacement?.phoneID)
                assertEquals(replacement.epoch, transcript.replacement?.epoch)
                val receipt = withTimeout(5000) { channel.submitProof(transcript.digest(), f.proof(transcript)) }
                assertTrue(transcript.verify(receipt, f.invitation.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
            } finally { channel?.closeAndJoin(); owner.cancelAndJoin() }
        }
    }

    @Test fun rePairRecoversTheLostReceiptOverTheNewKeyAfterArchiveReopen(): Unit = runBlocking {
        Fixture(rePair = true, dropRePairReceipt = true).use { f ->
            fun id(value: Int) = ByteArray(16) { value.toByte() }
            val invitation = checkNotNull(f.rePairInvitation)
            val proposal = f.proposal(replacement = invitation.predecessor)
            val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65_536)
            val storage = object : EnrollmentStorage {
                var contents: ByteArray? = null
                override fun read(maximumBytes: Int) = contents?.copyOf()
                override fun replace(ciphertext: ByteArray) { contents = ciphertext.copyOf() }
                override fun close() = Unit
            }
            fun oldKey(role: EnrollmentKeyRole): EnrollmentKeyReference {
                val pair = key()
                return EnrollmentKeyReference(role, id(30 + role.ordinal),
                    "remozio.${role.aliasPart}.v1.${"%032x".format(30 + role.ordinal)}",
                    if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else point(pair))
            }
            val predecessor = PhoneEnrollment(id(40), f.invitation.macID.copyBytes(), f.invitation.accountID.copyBytes(),
                invitation.predecessor.phoneID.copyBytes(), invitation.predecessor.epoch.copyBytes(), f.invitation.label,
                f.invitation.authorityPublicKey.copyBytes(), f.mac.certificate.publicKey.encoded,
                oldKey(EnrollmentKeyRole.TRANSPORT), oldKey(EnrollmentKeyRole.DECISION), oldKey(EnrollmentKeyRole.BIOMETRIC),
                ByteArray(32) { 41 }, null)
            val reservation = RePairReservation(id(42), predecessor.recordID.copyBytes(), id(4), invitation,
                listOf(proposal.transportKey.keyID, proposal.decisionKey.keyID, proposal.biometricKey.keyID))
            val material = RePairProposalMaterial(proposal, listOf(f.phone.keyPair, f.decision, f.biometric).mapIndexed { i, key ->
                val role = EnrollmentKeyRole.entries[i]
                EnrollmentKeyReference(role, reservation.keyIDs[i].copyBytes(), reservation.alias(role),
                    if (role == EnrollmentKeyRole.TRANSPORT) key.public.encoded else point(key))
            })
            val owner = SupervisorJob()
            val scope = CoroutineScope(owner)
            try {
                EncryptedEnrollmentStore.create(storage, cipher, 10).use { archive ->
                    archive.prepare(predecessor, 0u)
                    archive.remove(predecessor.recordID.copyBytes(), 1u)
                    archive.reserveRePair(reservation, 2u)
                    val channel = withTimeout(15_000) {
                        PairingSetupChannel.authenticate(scope, f.open(scope), f.keys, f.invitation, proposal)
                    }
                    try {
                        val transcript = channel.awaitTranscript {
                            archive.prepareRePairProposal(reservation.recordID, material, 3u)
                        }
                        archive.checkpointRePair(reservation.recordID, transcript, 4u)
                        rejectedWithin(5_000) {
                            channel.submitProof(transcript.digest(), f.proof(transcript)) {
                                archive.markRePairProof(reservation.recordID, 5u)
                            }
                        }
                    } finally { channel.closeAndJoin() }
                }
                EncryptedEnrollmentStore.open(storage, cipher, 10).use { archive ->
                    val row = archive.snapshot().entries.single { it.enrollment.recordID == reservation.recordID }
                    assertTrue(checkNotNull(row.rePair).proofMayHaveBeenSent)
                    val exchange = checkNotNull(row.pairing).transcript
                    val connector = ApprovalChannelConnector(f.keys, row.enrollment.transportPublicKey.copyBytes(),
                        exchange.phone.scope, emptyList(), emptySet(), PairingReceiptFrame.MAXIMUM_BYTES,
                        purpose = EnrolledChannelPurpose.PAIRING_RECEIPT)
                    val channel = connector.connect(scope, flowOf(ApprovalCarrierRoute { f.open(it, checkNotNull(f.receiptPort)) }), null)
                    val receipt = PairingReceiptChannel.bind(row, channel)
                    val proof = try { checkNotNull(receipt.recover()) } finally { receipt.closeAndJoin() }
                    val activated = archive.recoverPairing(reservation.recordID.copyBytes()).activate(archive, proof)
                    assertEquals(reservation.recordID, activated.entries.first().successorRecordID)
                    assertEquals(listOf(EnrollmentPhase.REMOVED, EnrollmentPhase.ACTIVE), activated.entries.map { it.phase })
                    assertEquals(activated.revision, archive.recoverPairing(reservation.recordID.copyBytes()).activate(archive, proof).revision)
                }
            } finally { owner.cancelAndJoin() }
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
    @Test fun idleNativeSetupReleasesDisconnectedCandidatesBeforeTheTimeout(): Unit = runBlocking {
        Fixture(holdPairingStage = true).use { f ->
            repeat(3) {
                val owner = SupervisorJob(); val scope = CoroutineScope(owner)
                var session: TLSRecordSession? = null
                try {
                    session = TLSRecordSession(scope, PinnedTLSClient(f.keys, f.mac.certificate.publicKey.encoded,
                        PairingSetupFrame.APPLICATION_PROTOCOL, 1_048_576), f.open(scope))
                    withTimeout(5000) {
                        session.awaitOpen()
                        val incoming = checkNotNull(session.receive())
                        assertTrue(incoming.size >= 4)
                        val length = incoming.take(4).fold(0) { n, b -> (n shl 8) or (b.toInt() and 255) }
                        val body = incoming.drop(4).toMutableList()
                        while (body.size < length) { body.addAll(checkNotNull(session.receive()).toList()) }
                        assertEquals(PairingSetupFrame.Hello, PairingSetupFrame.decode(body.toByteArray()))
                        val proposal = PairingSetupFrame.Proposal(f.proposal()).encode()
                        val size = proposal.size
                        session.send(byteArrayOf((size ushr 24).toByte(), (size ushr 16).toByte(), (size ushr 8).toByte(), size.toByte()) + proposal)
                        delay(200)
                    }
                } finally { session?.closeAndJoin(); owner.cancelAndJoin() }
                delay(300)
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
