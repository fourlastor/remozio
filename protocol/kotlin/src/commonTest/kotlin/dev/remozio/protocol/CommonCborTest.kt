package dev.remozio.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class CommonCborTest {
    private val limits = CborLimits(1_048_576, 32, 65_536)
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun sharedVectors() {
        val vectors = Json.parseToJsonElement(TestVectors.cborSubset).jsonArray
        assertTrue(vectors.size > 50)
        for (vector in vectors) {
            val fields = vector.jsonObject
            val name = fields.getValue("name").jsonPrimitive.content
            val bytes = hex(fields.getValue("hex").jsonPrimitive.content)
            if (fields.getValue("valid").jsonPrimitive.boolean) {
                assertContentEquals(bytes, DeterministicCbor.encode(DeterministicCbor.decode(bytes, limits), limits), name)
            } else {
                assertFailsWith<CborException>(name) { DeterministicCbor.decode(bytes, limits) }
            }
        }
    }

    @Test fun decodedCollectionsCannotBeMutatedThroughCasts() {
        val array = CborValue.ArrayValue(listOf(CborValue.Unsigned(1u)))
        assertFails { @Suppress("UNCHECKED_CAST") (array.values as MutableList<CborValue>).add(CborValue.Null) }
        val fields = CborValue.Fields(mapOf(1uL to CborValue.Null))
        assertFails { @Suppress("UNCHECKED_CAST") (fields.values as MutableMap<ULong, CborValue>)[2uL] = CborValue.Null }
    }
}
