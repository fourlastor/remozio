package dev.remozio.phone.push

import dev.remozio.protocol.*
import java.io.IOException
import java.util.UUID
import kotlin.test.*

class PendingWakeDemandTest {
    private class Storage : WakeDemandStorage {
        var bytes: ByteArray? = null
        var writes = 0
        var fail = false
        var failAfterCommit = false
        override fun read(maximumBytes: Int): ByteArray? {
            assertEquals(262_144, maximumBytes)
            return bytes?.copyOf()
        }
        override fun replace(bytes: ByteArray) {
            if (fail) throw IOException("Synthetic storage failure")
            this.bytes = bytes.copyOf(); writes++
            if (failAfterCommit) throw IOException("Synthetic uncertain replacement")
        }
    }
    private val generation = UUID(1, 2)
    private fun tag(n: Int) = ByteArray(32) { n.toByte() }
    private var revision = 0
    private fun open(storage: Storage, maximum: Int = 4) = PendingWakeDemand(storage, maximum) { tag(++revision) }

    @Test fun newerWakeSurvivesCompletionOfAnOlderFetchAndProcessRestart() {
        val disk = Storage(); val owner = open(disk); owner.selectGeneration(generation)
        val first = owner.mark(generation, tag(20))
        val newer = owner.mark(generation, tag(20))
        assertFalse(owner.complete(first))
        val restored = open(disk)
        assertEquals(1, restored.pending(generation).size)
        assertTrue(restored.complete(newer)); assertTrue(restored.pending(generation).isEmpty())
        assertTrue(open(disk).pending(generation).isEmpty()); assertFalse(restored.complete(first))
    }

    @Test fun completedDemandIsIndependentAcrossMacsAndDoesNotHoldRequestDetails() {
        val disk = Storage(); val owner = open(disk); owner.selectGeneration(generation)
        val a = owner.mark(generation, tag(20)); val b = owner.mark(generation, tag(21))
        assertTrue(owner.complete(a)); assertFalse(owner.complete(a))
        val retained = owner.pending(generation).single()
        assertEquals(b.tag, retained.tag); assertEquals("WakeDemandTicket(redacted)", retained.toString())
        assertTrue(owner.complete(b))
    }

    @Test fun capacityRefusesNewTagsButAllowsCoalescingAnExistingTag() {
        val disk = Storage(); val owner = open(disk, 1); owner.selectGeneration(generation)
        val initial = owner.mark(generation, tag(20)); val writes = disk.writes
        assertFails { owner.mark(generation, tag(21)) }; assertEquals(writes, disk.writes)
        val latest = owner.mark(generation, tag(20))
        assertFalse(owner.complete(initial)); assertTrue(owner.complete(latest))
    }

    @Test fun oldGenerationCannotMarkOrClearTheCurrentGeneration() {
        val disk = Storage(); val owner = open(disk); owner.selectGeneration(generation)
        val old = owner.mark(generation, tag(20)); val next = UUID(3, 4)
        owner.selectGeneration(next); val current = owner.mark(next, tag(20)); val writes = disk.writes
        assertFails { owner.mark(generation, tag(20)) }; assertFalse(owner.complete(old))
        assertTrue(owner.pending(generation).isEmpty()); assertEquals(writes, disk.writes)
        assertEquals(current.tag, open(disk).pending(next).single().tag)
        owner.selectGeneration(next); assertEquals(writes, disk.writes)
    }

    @Test fun uncertainWriteRetiresTheOwnerInsteadOfClearingNewerDurableDemand() {
        val disk = Storage(); val owner = open(disk); owner.selectGeneration(generation)
        val old = owner.mark(generation, tag(20))
        disk.failAfterCommit = true
        assertFailsWith<IOException> { owner.mark(generation, tag(20)) }
        disk.failAfterCommit = false
        assertFails { owner.complete(old) }; assertFails { owner.pending(generation) }
        assertFails { owner.mark(generation, tag(21)) }; assertFails { owner.selectGeneration(UUID(3, 4)) }
        val restored = open(disk); assertFalse(restored.complete(old))
        assertEquals(1, restored.pending(generation).size)
        assertTrue(restored.complete(restored.pending(generation).single()))
    }

    @Test fun failedCompletionPreservesDemandAndRequiresReopeningStorage() {
        val disk = Storage(); val owner = open(disk); owner.selectGeneration(generation)
        val ticket = owner.mark(generation, tag(20)); disk.fail = true
        assertFailsWith<IOException> { owner.complete(ticket) }
        assertFails { owner.pending(generation) }
        disk.fail = false; val restored = open(disk)
        assertEquals(1, restored.pending(generation).size); assertTrue(restored.complete(ticket))
    }

    @Test fun malformedOrOversizedStorageIsRefusedWithoutResetOrWrites() {
        val disk = Storage(); val owner = open(disk); owner.selectGeneration(generation); owner.mark(generation, tag(20))
        val limits = CborLimits(262_144, 4, 8192)
        val valid = (DeterministicCbor.decode(disk.bytes!!, limits) as CborValue.Fields).values
        val rows = (valid[3u] as CborValue.ArrayValue).values
        val malformed = listOf(byteArrayOf(0), ByteArray(262_145),
            DeterministicCbor.encode(CborValue.Fields(valid + (1uL to CborValue.Unsigned(2u))), limits),
            DeterministicCbor.encode(CborValue.Fields(valid + (4uL to CborValue.Null)), limits),
            DeterministicCbor.encode(CborValue.Fields(valid + (3uL to CborValue.ArrayValue(rows + rows))), limits))
        val writes = disk.writes
        for (bytes in malformed) {
            disk.bytes = bytes.copyOf(); assertFails { open(disk) }
            assertContentEquals(bytes, disk.bytes); assertEquals(writes, disk.writes)
        }
    }

    @Test fun invalidInputsAndRepeatedRevisionCannotMutateStoredDemand() {
        val disk = Storage(); val owner = PendingWakeDemand(disk, 1) { tag(30) }
        assertFails { owner.mark(generation, tag(20)) }
        owner.selectGeneration(generation); val ticket = owner.mark(generation, tag(20)); val writes = disk.writes
        assertFails { owner.mark(generation, tag(20)) }; assertFails { owner.mark(generation, ByteArray(31)) }
        assertEquals(writes, disk.writes); assertTrue(owner.complete(ticket))
    }
}
