package dev.remozio.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class DeterministicCborTest {
    private val limits = CborLimits(1_048_576, 32, 65_536)

    @Test
    fun sharedVectors() {
        val vectors = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.vectors"))).readText()).jsonArray
        assertTrue(vectors.size > 50)
        for (vector in vectors) {
            val fields = vector.jsonObject
            val name = fields.getValue("name").jsonPrimitive.content
            val bytes = hex(fields.getValue("hex").jsonPrimitive.content)
            if (fields.getValue("valid").jsonPrimitive.boolean) {
                val value = DeterministicCbor.decode(bytes, limits)
                assertContentEquals(bytes, DeterministicCbor.encode(value, limits), name)
            } else {
                assertFailsWith<CborException>(name) { DeterministicCbor.decode(bytes, limits) }
            }
        }
    }

    @Test
    fun decodedMeaningsAndMapOrdering() {
        val examples = listOf(
            "1bffffffffffffffff" to CborValue.Unsigned(ULong.MAX_VALUE),
            "4300ff80" to CborValue.Bytes(byteArrayOf(0, -1, -128)),
            "64f09f9982" to CborValue.Text("🙂"),
            "63efbbbf" to CborValue.Text("\uFEFF"),
            "64efbbbf61" to CborValue.Text("\uFEFFa"),
            "83001818f6" to CborValue.ArrayValue(listOf(CborValue.Unsigned(0u), CborValue.Unsigned(24u), CborValue.Null)),
            "a300f401f518186178" to CborValue.Fields(mapOf(
                24uL to CborValue.Text("x"), 1uL to CborValue.BooleanValue(true), 0uL to CborValue.BooleanValue(false),
            )),
        )
        for ((encoded, value) in examples) {
            assertEquals(value, DeterministicCbor.decode(hex(encoded), limits))
            assertContentEquals(hex(encoded), DeterministicCbor.encode(value, limits))
        }
    }

    @Test
    fun exactTextAndInvalidSurrogates() {
        val nfc = CborValue.Text("é")
        val decomposed = CborValue.Text("e\u0301")
        assertNotEquals(nfc, decomposed)
        assertContentEquals(hex("62c3a9"), DeterministicCbor.encode(nfc, limits))
        assertContentEquals(hex("6365cc81"), DeterministicCbor.encode(decomposed, limits))
        for (text in listOf("\uD800", "\uDC00", "\uD800x")) {
            assertFailure(CborFailure.INVALID_TEXT) { DeterministicCbor.encode(CborValue.Text(text), limits) }
        }
    }

    @Test
    fun immutableValues() {
        val source = byteArrayOf(1, 2)
        val bytes = CborValue.Bytes(source)
        source[0] = 9
        bytes.copyBytes()[0] = 8
        assertContentEquals(byteArrayOf(1, 2), bytes.copyBytes())
        val list = mutableListOf<CborValue>(bytes)
        val array = CborValue.ArrayValue(list)
        list.clear()
        assertEquals(listOf(bytes), array.values)
        assertFailsWith<UnsupportedOperationException> { (array.values as MutableList<*>).clear() }
        val map = mutableMapOf<ULong, CborValue>(0uL to array)
        val fields = CborValue.Fields(map)
        map.clear()
        assertEquals(mapOf(0uL to array), fields.values)
        assertFailsWith<UnsupportedOperationException> { (fields.values as MutableMap<*, *>).clear() }
        val input = hex("420102")
        val parsed = DeterministicCbor.decode(input, limits)
        input[1] = 9
        assertEquals(bytes, parsed)
    }

    @Test
    fun exactResourceBoundaries() {
        val oneByte = CborLimits(1, 0, 1)
        assertContentEquals(hex("17"), DeterministicCbor.encode(CborValue.Unsigned(23u), oneByte))
        assertEquals(CborValue.Unsigned(23u), DeterministicCbor.decode(hex("17"), oneByte))
        assertFailure(CborFailure.BYTE_LIMIT) { DeterministicCbor.encode(CborValue.Unsigned(24u), oneByte) }
        assertFailure(CborFailure.BYTE_LIMIT) { DeterministicCbor.decode(hex("1818"), oneByte) }
        val shallow = CborLimits(100, 1, 10)
        val nested = CborValue.ArrayValue(listOf(CborValue.ArrayValue(listOf(CborValue.Null))))
        assertFailure(CborFailure.DEPTH_LIMIT) { DeterministicCbor.encode(nested, shallow) }
        assertFailure(CborFailure.DEPTH_LIMIT) { DeterministicCbor.decode(hex("8181f6"), shallow) }
        assertEquals(CborValue.ArrayValue(listOf(CborValue.ArrayValue(emptyList()))), DeterministicCbor.decode(hex("8180"), shallow))
        val threeItems = CborLimits(100, 8, 3)
        val field = CborValue.Fields(mapOf(0uL to CborValue.Null))
        assertContentEquals(hex("a100f6"), DeterministicCbor.encode(field, threeItems))
        assertEquals(field, DeterministicCbor.decode(hex("a100f6"), threeItems))
        assertFailure(CborFailure.ITEM_LIMIT) { DeterministicCbor.decode(hex("83f6f6f6"), threeItems) }
        assertFailure(CborFailure.ITEM_LIMIT) {
            DeterministicCbor.encode(CborValue.ArrayValue(List(3) { CborValue.Null }), threeItems)
        }
        for (budget in listOf(Triple(0, 1, 1), Triple(1, -1, 1), Triple(1, 65, 1), Triple(1, 1, 0))) {
            assertFailure(CborFailure.INVALID_LIMITS) { CborLimits(budget.first, budget.second, budget.third) }
        }
        assertFailure(CborFailure.BYTE_LIMIT) { DeterministicCbor.encode(CborValue.Text("🙂"), CborLimits(4, 0, 1)) }
        assertContentEquals(hex("64f09f9982"), DeterministicCbor.encode(CborValue.Text("🙂"), CborLimits(5, 0, 1)))
    }

    @Test
    fun deterministicMalformedCorpus() {
        var random = 0x52454d4f5a494fuL
        repeat(10_000) {
            random = random * 6364136223846793005uL + 1uL
            val bytes = ByteArray((random % 64uL).toInt()) {
                random = random * 6364136223846793005uL + 1uL
                (random shr 32).toByte()
            }
            try {
                val value = DeterministicCbor.decode(bytes, limits)
                assertContentEquals(bytes, DeterministicCbor.encode(value, limits))
            } catch (_: CborException) {
                // Rejection is expected; other exceptions fail the corpus run.
            }
        }
    }

    private fun assertFailure(reason: CborFailure, action: () -> Any?) {
        assertEquals(reason, assertFailsWith<CborException> { action() }.reason)
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
