package dev.sebastiano.remozio.android.requests

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

class ByteTextTest {
    private fun quoted(value: String) = ByteText.quoted(value.encodeToByteArray())
    @Test fun quotesEmptyArgumentsAndEscapesLiteralSyntax() {
        assertEquals("\"\"", quoted(""))
        assertEquals("\"a b\"", quoted("a b"))
        assertEquals("\"\\\"\\\\\\n\\r\\t\"", quoted("\"\\\n\r\t"))
        assertNotEquals(quoted("\\n"), quoted("\n"))
        assertNotEquals(quoted("\\xff"), ByteText.quoted(byteArrayOf(0xff.toByte())))
    }
    @Test fun makesControlsAndBidiVisible() {
        assertEquals("\"\\u{0}\\u{1b}\\u{7f}\\u{85}\\u{a0}\\u{2028}\\u{2029}\\u{202e}\\u{2066}\\u{feff}\"",
            quoted("\u0000\u001b\u007f\u0085\u00a0\u2028\u2029\u202e\u2066\ufeff"))
    }
    @Test fun preservesReadableUnicodeAndExactByteExpansion() {
        assertEquals("\"café 日本語 🙂\"", quoted("café 日本語 🙂"))
        assertNotEquals(quoted("é"), quoted("e\u0301"))
        assertEquals("c3 a9", ByteText.hex("é".encodeToByteArray()))
        assertEquals("65 cc 81", ByteText.hex("e\u0301".encodeToByteArray()))
        assertEquals("", ByteText.hex(byteArrayOf()))
    }
    @Test fun neverReplacesMalformedUtf8() {
        val cases = listOf(
            "80" to "\\x80", "c0af" to "\\xc0\\xaf", "e080af" to "\\xe0\\x80\\xaf",
            "eda080" to "\\xed\\xa0\\x80", "f4908080" to "\\xf4\\x90\\x80\\x80",
            "f5808080" to "\\xf5\\x80\\x80\\x80", "e282" to "\\xe2\\x82", "e228a1" to "\\xe2(\\xa1",
        )
        for ((hex, expected) in cases) {
            val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            assertEquals("\"$expected\"", ByteText.quoted(bytes), hex)
            assertFalse(ByteText.quoted(bytes).contains('\ufffd'))
        }
    }
    @Test fun preservesEveryByteInTheHexView() {
        val bytes = ByteArray(256) { it.toByte() }
        val decoded = ByteText.hex(bytes).split(' ').map { it.toInt(16).toByte() }.toByteArray()
        assertEquals(bytes.toList(), decoded.toList())
        val long = ByteArray(20_000) { 'a'.code.toByte() }
        assertEquals(20_002, ByteText.quoted(long).length)
    }
}
