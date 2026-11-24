package dev.remozio.phone.transport

import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.P256SignatureEncoding
import dev.remozio.protocol.PairingRecoveryFrame
import dev.remozio.protocol.PairingRecoveryQuery
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PairingRecoveryChannelTest {
    private val query = PairingRecoveryQuery(ByteArray(16) { 1 }, ByteArray(32) { 2 },
        ChannelScope(ByteArray(16) { 3 }, ByteArray(16) { 4 }, ByteArray(16) { 5 }, ByteArray(16) { 6 }))
    private val exporter = ByteArray(32) { 7 }
    private val challenge = ByteArray(32) { 8 }

    private fun wire(frame: PairingRecoveryFrame): ByteArray =
        frame.encode().let { ByteBuffer.allocate(4 + it.size).putInt(it.size).put(it).array() }

    @Test fun fragmentedLookupUsesOneCandidateProofAndOneReply() = runBlocking<Unit> {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val outgoing = mutableListOf<ByteArray>()
        val incoming = ArrayDeque(listOf(
            wire(PairingRecoveryFrame.Challenge(challenge)).copyOfRange(0, 2),
            wire(PairingRecoveryFrame.Challenge(challenge)).copyOfRange(2, 37),
            wire(PairingRecoveryFrame.Committed(ByteArray(64))),
        ))
        val result = PairingRecoveryChannel.exchange(query, exporter, { outgoing.add(it) }, { incoming.removeFirstOrNull() },
            { attempt, tls, nonce ->
                assertContentEquals(challenge, nonce)
                P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                    initSign(key.private)
                    update(attempt.signingInput(tls, nonce))
                    sign()
                })
            }, {})
        assertIs<PairingRecoveryFrame.Committed>(result)
        assertEquals(2, outgoing.size)
        assertContentEquals(wire(PairingRecoveryFrame.Lookup(query)), outgoing[0])
        val proof = assertIs<PairingRecoveryFrame.Proof>(PairingRecoveryFrame.decode(outgoing[1].copyOfRange(4, outgoing[1].size)))
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(key.public)
            update(query.signingInput(exporter, challenge))
            verify(P256SignatureEncoding.toDer(proof.signature.copyBytes()))
        })
    }

    @Test fun rejectsOversizedTruncatedAndUnexpectedChallengeFrames() = runBlocking<Unit> {
        for (bytes in listOf(
            ByteBuffer.allocate(4).putInt(PairingRecoveryFrame.MAXIMUM_BYTES + 1).array(),
            wire(PairingRecoveryFrame.Challenge(challenge)).copyOf(15),
            wire(PairingRecoveryFrame.Refused),
            wire(PairingRecoveryFrame.Challenge(challenge)) + byteArrayOf(0),
        )) {
            val incoming = ArrayDeque(listOf(bytes))
            var sent = 0
            assertFails {
                PairingRecoveryChannel.exchange(query, exporter, { sent++ }, { incoming.removeFirstOrNull() },
                    { _, _, _ -> error("Invalid challenge was signed") }, {})
            }
            assertEquals(1, sent)
        }
    }

    @Test fun leaseInvalidationAfterSigningPreventsSendingTheProof() = runBlocking<Unit> {
        var current = true
        var sent = 0
        assertFails {
            PairingRecoveryChannel.exchange(query, exporter, { sent++ }, { wire(PairingRecoveryFrame.Challenge(challenge)) },
                { _, _, _ -> current = false; ByteArray(64) }, { check(current) })
        }
        assertEquals(1, sent)
    }
}
