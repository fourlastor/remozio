package dev.remozio.protocol

import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CompatibilityPolicyTest {
    private val a = UUID(0, 1)
    private val b = UUID(0, 2)
    private val c = UUID(0, 3)

    @Test
    fun envelopeIntersectionAndTrustedFloor() {
        assertEquals(3uL, CompatibilityPolicy.envelopeVersion(setOf(1u, 3u, 5u), setOf(1u, 2u, 3u), 1u))
        assertEquals(1uL, CompatibilityPolicy.envelopeVersion(setOf(1u, 3u), setOf(1u), 1u))
        assertEquals(CompatibilityFailure.NO_SAFE_ENVELOPE_VERSION, assertFailsWith<CompatibilityException> {
            CompatibilityPolicy.envelopeVersion(setOf(1u, 3u), setOf(1u), 2u)
        }.reason)
        assertFailsWith<CompatibilityException> { CompatibilityPolicy.envelopeVersion(setOf(1u), setOf(2u), 1u) }
        assertFailsWith<CompatibilityException> { CompatibilityPolicy.envelopeVersion(setOf(1u), setOf(1u), 0u) }
    }

    @Test
    fun mostReachableContractThenNewestTie() {
        val old = contract(1u)
        val new = contract(2u)
        val all = capabilities(old, new)
        val phones = mapOf(a to all, b to capabilities(old), c to capabilities(old))
        val result = select(all, phones, setOf(old, new))
        assertEquals(old, result.contract)
        assertEquals(setOf(a, b, c), result.eligibleEnrollments)
        val tie = select(all, mapOf(a to all, b to all), setOf(old, new))
        assertEquals(new, tie.contract)
        assertEquals(setOf(a, b), tie.eligibleEnrollments)
    }

    @Test
    fun securityPolicyAndFeaturesExcludeMorePopularOldContract() {
        val old = contract(1u)
        val new = contract(2u)
        val all = capabilities(old, new)
        val phones = mapOf(a to all, b to capabilities(old), c to capabilities(old))
        val result = select(all, phones, setOf(new))
        assertEquals(new, result.contract)
        assertEquals(setOf(a), result.eligibleEnrollments)
        val missingFeature = ContractCapabilities(mapOf(new to emptySet()))
        assertFailsWith<CompatibilityException> { select(all, mapOf(a to missingFeature), setOf(new)) }
        assertFailsWith<CompatibilityException> { select(missingFeature, mapOf(a to all), setOf(new)) }
    }

    @Test
    fun requestKindsAndSchemaVersionsStaySeparate() {
        val schema1 = contract(1u)
        val schema2 = contract(1u, 2u)
        val firewall = RequestContract(RequestKind.LITTLE_SNITCH, 9u, 9u)
        val all = capabilities(schema1, schema2, firewall)
        val result = select(all, mapOf(a to all), setOf(schema1, schema2, firewall))
        assertEquals(schema2, result.contract)
        assertFailsWith<CompatibilityException> { select(all, mapOf(a to capabilities(firewall)), setOf(firewall)) }
        assertFailsWith<CompatibilityException> { select(all, emptyMap(), setOf(schema1)) }
        assertFailsWith<CompatibilityException> { RequestContract(RequestKind.COMMAND, 0u, 1u) }
        assertFailsWith<CompatibilityException> { RequestContract(RequestKind.COMMAND, 1u, 0u) }
    }

    @Test
    fun capabilitiesRetainAnImmutableSnapshot() {
        val contract = contract(1u)
        val features = mutableSetOf(7uL)
        val map: MutableMap<RequestContract, Set<ULong>> = mutableMapOf(contract to features)
        val snapshot = ContractCapabilities(map)
        features.clear()
        map.clear()
        assertEquals(setOf(7uL), snapshot.contracts.getValue(contract))
        assertFailsWith<UnsupportedOperationException> { (snapshot.contracts as MutableMap<*, *>).clear() }
        assertFailsWith<UnsupportedOperationException> { (snapshot.contracts.getValue(contract) as MutableSet<*>).clear() }
    }

    private fun contract(wire: ULong, schema: ULong = 1u) = RequestContract(RequestKind.COMMAND, wire, schema)
    private fun capabilities(vararg contracts: RequestContract) = ContractCapabilities(contracts.associateWith { setOf(7uL) })
    private fun select(authority: ContractCapabilities, phones: Map<UUID, ContractCapabilities>, allowed: Set<RequestContract>) =
        CompatibilityPolicy.requestContract(RequestKind.COMMAND, authority, phones, allowed, setOf(7u))
}
