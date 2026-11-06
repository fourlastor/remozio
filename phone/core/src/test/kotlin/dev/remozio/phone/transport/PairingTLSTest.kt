package dev.remozio.phone.transport

import dev.remozio.pairing.PairingSetupChannel
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.KeyManager
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import org.junit.Test
import kotlin.test.*

class PairingTLSTest {
    private fun point(): ByteArray {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val w = (key.public as ECPublicKey).w
        fun scalar(n: java.math.BigInteger): ByteArray = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
        return byteArrayOf(4) + scalar(w.affineX) + scalar(w.affineY)
    }
    private class Carrier : EncryptedRecordTransport {
        override val maximumMessageBytes = 16_384
        private val inbound = Channel<ByteArray?>(Channel.UNLIMITED)
        @Volatile var closes = 0
        @Volatile var joins = 0
        override suspend fun send(ciphertext: ByteArray) {}
        override suspend fun receive(): ByteArray? = inbound.receive()
        override suspend fun awaitClosed() { joins++ }
        override fun close() { closes++; inbound.trySend(null) }
    }

    @Test fun aProposalForAnotherMacStillClosesAndJoinsTheCarrier(): Unit = runBlocking {
        val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
        val offer = ChannelOffer(ChannelRole.PHONE, scope, ByteArray(32) { 5 }, setOf(1u), emptyList(), emptySet())
        val proposal = PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 6 }, point()),
            PairingKey(ByteArray(16) { 7 }, point()), PairingKey(ByteArray(16) { 8 }, point()))
        val other = PairingInvitation(ByteArray(16) { 0x55 }, ByteArray(16) { 0x66 }, "Other", point(), point(), 1u)
        val carrier = Carrier(); val parent = SupervisorJob()
        try {
            assertFails { PairingSetupChannel.connect(CoroutineScope(parent), carrier, arrayOf<KeyManager>(), other, proposal) }
        } finally { parent.cancelAndJoin() }
        assertTrue(carrier.closes >= 1 && carrier.joins >= 1, "closes=${carrier.closes} joins=${carrier.joins}")
    }
}
