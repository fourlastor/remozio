package dev.remozio.protocol

import java.io.File
import kotlinx.serialization.json.*
import org.junit.Test
import kotlin.test.*

class ChannelNegotiationTest {
    private val vectors get() = Json.parseToJsonElement(File(System.getProperty("remozio.channelVectors")).readText()).jsonObject
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun bytes(name: String) = hex(vectors.getValue(name).jsonPrimitive.content)
    private fun offer(name: String) = ChannelOffer.decode(bytes(name))
    private fun pair(): Pair<ChannelNegotiation, ChannelNegotiation> {
        val phone = ChannelNegotiation(offer("phone"), 1u)
        val mac = ChannelNegotiation(offer("mac"), 1u)
        val p = phone.offer(); val m = mac.offer()
        phone.receiveOffer(m); mac.receiveOffer(p)
        return phone to mac
    }
    @Test fun sharedOffersAndOpaqueFutureKindsRoundTrip() {
        for (name in listOf("phone", "mac")) assertContentEquals(bytes(name), offer(name).encode())
        assertEquals(99uL, offer("phone").requests[1].kind)
        assertTrue(offer("mac").auditVersions.isEmpty())
    }
    @Test fun sharedTranscriptAndConfirmationsAgree() {
        val (phone, mac) = pair()
        assertFails { phone.confirmed() }; assertFails { mac.confirmed() }
        val p = phone.confirmation(); assertContentEquals(bytes("phoneConfirmation"), p)
        mac.receiveConfirmation(p)
        assertFails { mac.confirmed() }
        val m = mac.confirmation(); assertContentEquals(bytes("macConfirmation"), m)
        phone.receiveConfirmation(m)
        for (owner in listOf(phone, mac)) {
            assertEquals(3uL, owner.confirmed().envelopeVersion)
            assertContentEquals(bytes("sessionID"), owner.confirmed().sessionID.copyBytes())
            owner.close(); assertFails { owner.confirmed() }
        }
    }
    @Test fun malformedAndNoncanonicalOffersFail() {
        for (row in vectors.getValue("invalid").jsonArray) {
            assertFails(row.jsonObject.getValue("name").jsonPrimitive.content) {
                ChannelOffer.decode(hex(row.jsonObject.getValue("hex").jsonPrimitive.content))
            }
        }
        assertFails { ChannelOffer.decode(ByteArray(65_537)) }
    }
    @Test fun reflectionWrongScopeAndReusedNoncePermanentlyCloseTheOwner() {
        val local = offer("phone"); val remote = offer("mac")
        val wrongScope = ChannelScope(ByteArray(16), ByteArray(16), ByteArray(16), ByteArray(16))
        val bad = listOf(local, ChannelOffer(remote.role, wrongScope, remote.nonce.copyBytes(), remote.envelopeVersions, remote.requests, remote.auditVersions),
            ChannelOffer(remote.role, remote.scope, local.nonce.copyBytes(), remote.envelopeVersions, remote.requests, remote.auditVersions))
        for (value in bad) {
            val owner = ChannelNegotiation(local, 1u); owner.offer()
            assertFails { owner.receiveOffer(value.encode()) }
            assertFails { owner.receiveOffer(remote.encode()) }
        }
    }
    @Test fun wrongConfirmationAndCrossSessionReplayFailClosed() {
        for (wrong in listOf(bytes("phoneConfirmation"), bytes("macConfirmation").also { it[it.lastIndex] = 0 }, ByteArray(129))) {
            val (phone, _) = pair(); phone.confirmation()
            assertFails { phone.receiveConfirmation(wrong) }
            assertFails { phone.receiveConfirmation(bytes("macConfirmation")) }
        }
        val local = offer("phone")
        val fresh = ChannelOffer(local.role, local.scope, ByteArray(32) { 8 }, local.envelopeVersions, local.requests, local.auditVersions)
        val owner = ChannelNegotiation(fresh, 1u); owner.offer(); owner.receiveOffer(bytes("mac")); owner.confirmation()
        assertFails { owner.receiveConfirmation(bytes("macConfirmation")) }
    }
    @Test fun orderingDuplicatesAndLocalFloorAreEnforced() {
        val (phone, mac) = pair()
        assertFails { mac.confirmation() }; assertFails { mac.receiveConfirmation(phone.confirmation()) }
        val (p2, _) = pair(); assertFails { p2.receiveOffer(bytes("mac")) }; assertFails { p2.confirmation() }
        val p3 = ChannelNegotiation(offer("phone"), 4u); p3.offer()
        assertFailsWith<CompatibilityException> { p3.receiveOffer(bytes("mac")) }; assertFails { p3.confirmation() }
        val p4 = ChannelNegotiation(offer("phone"), 1u)
        assertFails { p4.receiveOffer(bytes("mac")) }; assertFails { p4.offer() }
    }
    @Test fun alteredCapabilitiesCannotProduceMatchingConfirmation() {
        for (changed in vectors.getValue("tamperedMacOffers").jsonArray) {
            val phone = ChannelNegotiation(offer("phone"), 1u)
            val mac = ChannelNegotiation(offer("mac"), 1u)
            val p = phone.offer(); mac.offer()
            phone.receiveOffer(hex(changed.jsonPrimitive.content)); mac.receiveOffer(p)
            assertFails { mac.receiveConfirmation(phone.confirmation()) }
            assertFails { mac.confirmed() }
        }
    }
    @Test fun offersKeepDefensiveCopiesAndRedactDescriptions() {
        val base = offer("phone"); val nonce = base.nonce.copyBytes(); val versions = mutableSetOf(1uL)
        val value = ChannelOffer(base.role, base.scope, nonce, versions, base.requests, emptySet())
        nonce.fill(0); versions.clear()
        assertEquals(setOf(1uL), value.envelopeVersions); assertEquals(base.nonce, value.nonce)
        assertEquals("ChannelOffer(redacted)", value.toString())
        assertFails { (value.envelopeVersions as MutableSet<ULong>).clear() }
    }
}
