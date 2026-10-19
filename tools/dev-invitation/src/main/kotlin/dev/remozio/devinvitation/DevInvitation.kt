package dev.remozio.devinvitation

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import dev.remozio.protocol.PairingInvitation
import java.awt.image.BufferedImage
import java.io.File
import java.net.InetAddress
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.imageio.ImageIO
import kotlin.system.exitProcess

/**
 * Development-only invitation for phone import tests. No host holds the private keys, so no pairing can complete.
 * It is not a Linux host and is never part of an app or release.
 */
fun newInvitation(label: String, random: SecureRandom = SecureRandom()): PairingInvitation {
    val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1"), random) }
    // The private halves are discarded when this function returns.
    val authority = generator.generateKeyPair().public as ECPublicKey
    val transport = generator.generateKeyPair().public as ECPublicKey
    fun id() = ByteArray(16).also(random::nextBytes)
    return PairingInvitation(id(), id(), label, uncompressedPoint(authority), uncompressedPoint(transport), 1uL)
}

/** The 65-byte `0x04 || X || Y` form that the invitation requires; `getEncoded()` would be X.509 SPKI. */
fun uncompressedPoint(key: ECPublicKey): ByteArray {
    fun coordinate(value: java.math.BigInteger): ByteArray {
        val bytes = value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        require(bytes.size <= 32)
        return ByteArray(32 - bytes.size) + bytes
    }
    return byteArrayOf(4) + coordinate(key.w.affineX) + coordinate(key.w.affineY)
}

/** Printable ASCII from the host name plus " (dev)", within the invitation's 200-byte label limit. */
fun labelFromHostname(hostname: String?): String {
    val base = hostname.orEmpty().filter { it in '!'..'~' }.take(200 - DEV_SUFFIX.length)
    return (base.ifEmpty { "linux" }) + DEV_SUFFIX
}

fun hex(bytes: ByteArray): String = bytes.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }

fun qrMatrix(text: String): BitMatrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(
    EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
    EncodeHintType.MARGIN to 4,
))

fun qrImage(text: String, moduleSize: Int = 8): BufferedImage {
    val matrix = qrMatrix(text)
    val image = BufferedImage(matrix.width * moduleSize, matrix.height * moduleSize, BufferedImage.TYPE_BYTE_BINARY)
    for (y in 0 until image.height) for (x in 0 until image.width) {
        image.setRGB(x, y, if (matrix[x / moduleSize, y / moduleSize]) 0x000000 else 0xffffff)
    }
    return image
}

private const val DEV_SUFFIX = " (dev)"
private const val USAGE = "Usage: dev-invitation [--label <text>] [--png <path>]"

fun main(args: Array<String>) {
    var label: String? = null
    var png = "dev-invitation.png"
    var index = 0
    while (index < args.size) {
        val value = args.getOrNull(index + 1)
        when {
            args[index] == "--label" && value != null -> label = value
            args[index] == "--png" && value != null -> png = value
            else -> { System.err.println(USAGE); exitProcess(2) }
        }
        index += 2
    }
    val chosen = label ?: labelFromHostname(runCatching { InetAddress.getLocalHost().hostName }.getOrNull())
    val invitation = try {
        newInvitation(chosen)
    } catch (_: IllegalArgumentException) {
        System.err.println("The label is not valid for an invitation: 1 to 200 UTF-8 bytes, not only spaces, " +
            "no control, line-separator or direction-control characters.")
        exitProcess(2)
    }
    val text = invitation.exportText()
    val file = File(png)
    check(ImageIO.write(qrImage(text), "png", file)) { "No PNG writer is available" }
    println("""
        |Development invitation. This is a test fixture: no computer holds its keys, so pairing cannot complete.
        |Mac ID:      ${hex(invitation.macID.copyBytes())}
        |Account ID:  ${hex(invitation.accountID.copyBytes())}
        |Label:       ${invitation.label}
        |Fingerprint: ${invitation.fingerprint()}
        |QR code:     ${file.absolutePath}
        |Text:
        |$text
    """.trimMargin())
}
