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
        assertFails { @Suppress("UNCHECKED_CAST") (fields.values as MutableMap<ULong, CborValue>).put(2uL, CborValue.Null) }
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun viewsOfDecodedCollectionsCannotBeMutatedThroughCasts() {
        val list = CborValue.ArrayValue(listOf(CborValue.Unsigned(1u), CborValue.Unsigned(2u))).values
        assertFails { (list.subList(0, 1) as MutableList<CborValue>).clear() }
        assertFails { (list.iterator() as MutableIterator<CborValue>).apply { next() }.remove() }
        assertFails { (list.listIterator() as MutableListIterator<CborValue>).apply { next() }.set(CborValue.Null) }
        assertFails { (list.listIterator(1) as MutableListIterator<CborValue>).add(CborValue.Null) }
        val map = CborValue.Fields(mapOf(1uL to CborValue.Null, 2uL to CborValue.Unsigned(3u))).values
        assertFails { (map.keys as MutableSet<ULong>).clear() }
        assertFails { (map.values as MutableCollection<CborValue>).clear() }
        assertFails { (map.entries as MutableSet<Map.Entry<ULong, CborValue>>).clear() }
        assertFails { (map.keys.iterator() as MutableIterator<ULong>).apply { next() }.remove() }
        assertFails { (map.entries.first() as MutableMap.MutableEntry<ULong, CborValue>).setValue(CborValue.Unsigned(4u)) }
        assertTrue(list == listOf(CborValue.Unsigned(1u), CborValue.Unsigned(2u)))
        assertTrue(map == mapOf(1uL to CborValue.Null, 2uL to CborValue.Unsigned(3u)))
    }
}
