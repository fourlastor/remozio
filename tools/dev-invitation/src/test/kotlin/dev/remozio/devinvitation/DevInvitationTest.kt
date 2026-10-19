package dev.remozio.devinvitation

import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import dev.remozio.protocol.PairingInvitation
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DevInvitationTest {
    @Test fun exportedTextRoundTripsThroughTheStrictParser() {
        val invitation = newInvitation("dev-box (dev)")
        val imported = PairingInvitation.importText(invitation.exportText())
        assertEquals(invitation.fingerprint(), imported.fingerprint())
        assertEquals(hex(invitation.macID.copyBytes()), hex(imported.macID.copyBytes()))
        assertEquals("dev-box (dev)", imported.label)
        assertEquals(1uL, imported.minimumEnvelopeVersion)
    }

    @Test fun pointsAreUncompressedOnTheCurveAndDistinct() {
        val invitation = newInvitation("points (dev)")
        val authority = invitation.authorityPublicKey.copyBytes()
        val transport = invitation.transportPublicKey.copyBytes()
        for (point in listOf(authority, transport)) {
            assertEquals(65, point.size)
            assertEquals(4, point[0].toInt())
            assertTrue(onP256(point))
        }
        assertFalse(authority.contentEquals(transport))
    }

    @Test fun twoRunsGiveDifferentIdentities() {
        val first = newInvitation("a (dev)")
        val second = newInvitation("a (dev)")
        assertFalse(first.macID.copyBytes().contentEquals(second.macID.copyBytes()))
        assertFalse(first.accountID.copyBytes().contentEquals(second.accountID.copyBytes()))
        assertFalse(first.authorityPublicKey.copyBytes().contentEquals(second.authorityPublicKey.copyBytes()))
    }

    @Test fun hostnameLabelsAlwaysPassTheParserRules() {
        val hostnames = listOf(null, "", "   ", "dev-box", "host\u0007name", "evil‮eman", "café x",
            "\u0000\u0085‏", "x".repeat(400), "😀emoji")
        for (hostname in hostnames) {
            val label = labelFromHostname(hostname)
            assertTrue(label.endsWith(" (dev)"))
            assertTrue(label.encodeToByteArray().size <= 200)
            PairingInvitation.importText(newInvitation(label).exportText())
        }
        assertEquals("linux (dev)", labelFromHostname("‮"))
    }

    @Test fun qrImageDecodesToTheExactText() {
        val text = newInvitation("qr (dev)").exportText()
        val image = qrImage(text)
        val pixels = IntArray(image.width * image.height)
        image.getRGB(0, 0, image.width, image.height, pixels, 0, image.width)
        val bitmap = BinaryBitmap(HybridBinarizer(RGBLuminanceSource(image.width, image.height, pixels)))
        // The image is generated, so skip ZXing's finder-pattern search; it misses about 1 in 30 random codes.
        assertEquals(text, QRCodeReader().decode(bitmap, mapOf(DecodeHintType.PURE_BARCODE to true)).text)
    }

    private fun onP256(point: ByteArray): Boolean {
        val p = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
        val b = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
        val x = BigInteger(1, point.copyOfRange(1, 33))
        val y = BigInteger(1, point.copyOfRange(33, 65))
        return x < p && y < p && y.pow(2).mod(p) == (x.pow(3) - x * BigInteger.valueOf(3) + b).mod(p)
    }
}
