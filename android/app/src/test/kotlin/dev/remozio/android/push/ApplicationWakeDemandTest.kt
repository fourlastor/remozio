package dev.remozio.android.push

import dev.remozio.protocol.CborValue
import org.junit.Test
import kotlin.test.*

class ApplicationWakeDemandTest {
    private class Fixture {
        val client = PushClientFixture().also { it.enable() }
        val disk = WakeTestJournal()
        val owner = ApplicationWakeDemand(client.owner, disk::open)
        val generation get() = assertNotNull(client.owner.generation())
        val first = CborValue.Bytes(ByteArray(32) { 1 })
        val second = CborValue.Bytes(ByteArray(32) { 2 })
    }
    @Test fun uncertainCommitReopensDurableStateAndDoesNotResetIt() {
        val f = Fixture(); f.owner.pending(f.generation, setOf(f.first)); f.disk.commitThenThrow = true
        assertFails { f.owner.admit(f.generation, f.first, setOf(f.first)) }
        assertEquals(1, f.disk.closes)
        f.disk.commitThenThrow = false
        val restored = f.owner.pending(f.generation, setOf(f.first))
        assertEquals(f.first, restored.single().tag); assertEquals(2, f.disk.opens)
    }
    @Test fun failedWriteRetiresOwnerWithoutInventingCommittedDemand() {
        val f = Fixture(); f.disk.failure = true
        assertFails { f.owner.admit(f.generation, f.first, setOf(f.first)) }
        f.disk.failure = false
        assertTrue(f.owner.pending(f.generation, setOf(f.first)).isEmpty()); assertEquals(2, f.disk.opens)
    }
    @Test fun oldGenerationCannotSelectOrClearANewerGeneration() {
        val f = Fixture(); val old = f.generation
        f.owner.admit(old, f.first, setOf(f.first)); val ticket = f.owner.pending(old, setOf(f.first)).single()
        f.client.owner.setEnabled(false); f.client.owner.setEnabled(true)
        f.owner.admit(f.generation, f.second, setOf(f.second))
        val bytes = f.disk.bytes!!.copyOf()
        f.owner.admit(old, f.first, setOf(f.first)); assertFalse(f.owner.complete(ticket))
        assertTrue(f.owner.pending(old, setOf(f.first)).isEmpty())
        assertContentEquals(bytes, f.disk.bytes)
        assertEquals(f.second, f.owner.pending(f.generation, setOf(f.second)).single().tag)
    }
    @Test fun exactCompletionAndTrustedPruningPreserveAnotherMac() {
        val f = Fixture(); val tags = setOf(f.first, f.second)
        f.owner.admit(f.generation, f.first, tags); val old = f.owner.pending(f.generation, tags).single()
        f.owner.admit(f.generation, f.first, tags); f.owner.admit(f.generation, f.second, tags)
        assertFalse(f.owner.complete(old)); assertEquals(2, f.owner.pending(f.generation, tags).size)
        assertEquals(f.second, f.owner.pending(f.generation, setOf(f.second)).single().tag)
    }
    @Test fun invalidSelectedTagCannotPruneValidDemand() {
        val f = Fixture(); f.owner.admit(f.generation, f.first, setOf(f.first)); val bytes = f.disk.bytes!!.copyOf()
        assertFailsWith<IllegalArgumentException> { f.owner.admit(f.generation, f.second, emptySet()) }
        assertContentEquals(bytes, f.disk.bytes)
    }
    @Test fun malformedStorageIsNeverResetAndFactoryFailureCanRecover() {
        val f = Fixture(); f.disk.bytes = byteArrayOf(1, 2, 3)
        repeat(2) { assertFails { f.owner.pending(f.generation, setOf(f.first)) } }
        assertContentEquals(byteArrayOf(1, 2, 3), f.disk.bytes)
        var fail = true
        val next = ApplicationWakeDemand(f.client.owner) { check(!fail); WakeTestJournal().open() }
        assertFails { next.pending(f.generation, setOf(f.first)) }; fail = false
        assertTrue(next.pending(f.generation, setOf(f.first)).isEmpty())
    }
    @Test fun closeCannotBeBypassedByReopening() {
        val f = Fixture(); f.owner.pending(f.generation, emptySet()); f.owner.close(); f.owner.close()
        assertEquals(1, f.disk.closes)
        assertFailsWith<IllegalStateException> { f.owner.pending(f.generation, emptySet()) }; assertEquals(1, f.disk.opens)
    }
}
