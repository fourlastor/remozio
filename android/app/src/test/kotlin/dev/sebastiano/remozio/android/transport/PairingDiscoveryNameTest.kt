package dev.sebastiano.remozio.android.transport

import dev.remozio.protocol.PairingInvitation
import dev.remozio.protocol.PairingInvitationV2
import dev.remozio.protocol.PairingReplacement
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import org.junit.Test

class PairingDiscoveryNameTest {
    private fun key(): ByteArray = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair().public.encoded.takeLast(65).toByteArray()

    @Test
    fun selectsTheWindowNameForV2PairingAndReplacement() {
        val invitation = PairingInvitation(ByteArray(16) { 1 }, ByteArray(16) { 2 }, "Mac", key(), key(), 1u)
        val first = PairingInvitationV2(invitation, ByteArray(16) { it.toByte() }, ByteArray(32), lifetimeMilliseconds = 1000u)
        val replacement = PairingInvitationV2(invitation, ByteArray(16) { (it + 16).toByte() }, ByteArray(32),
            replacement = PairingReplacement(ByteArray(16) { 3 }, ByteArray(16) { 4 }), lifetimeMilliseconds = 1000u)

        val legacyName = pairingServiceName(invitation, null)
        val firstName = pairingServiceName(invitation, PairingInvitationV2.importText(first.exportText()))
        val replacementName = pairingServiceName(invitation, PairingInvitationV2.importText(replacement.exportText()))
        assertEquals("R-AQEBAQEBAQEBAQEBAQEBAQ-AgICAgICAgICAgICAgICAg", legacyName)
        assertEquals("R2-9258385a87e7bf9effea002e90c5eabe", firstName)
        assertEquals("R2-64d394db60592bcc0b3f6014c1692e37", replacementName)
        assertNotEquals(legacyName, replacementName)
        assertNotEquals(firstName, replacementName)
    }
}
