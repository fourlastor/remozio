package dev.remozio.phone.enrollment

import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import kotlin.test.*

/** The JVM and iOS locks and read-only lists are separate code, so both targets run these. */
class EnrollmentStoreOwnershipTest {
    private val vector = archiveVector()
    private val maximumRecords = vector.getValue("maximumRecords").jsonPrimitive.int
    private val cipher = EnrollmentCipher(PlainAead, vector.getValue("maximumPlaintextBytes").jsonPrimitive.int)
    private fun disk() = Disk(cipher.encrypt(vector.hex("plaintextSchema2")))
    private fun open(disk: Disk) = EncryptedEnrollmentStore.open(disk, cipher, maximumRecords)

    @Test fun onlyOneOfManyWritersAtTheSameRevisionCommits() = runTest {
        val disk = disk()
        val store = open(disk)
        val before = store.snapshot()
        val record = before.entries.first().enrollment.recordID.copyBytes()
        val outcomes = withContext(Dispatchers.Default) {
            List(64) { async { runCatching { store.remove(record, before.revision) } } }.awaitAll()
        }
        assertEquals(1, outcomes.count { it.isSuccess })
        assertEquals(1, disk.writes)
        assertEquals(before.revision + 1u, store.snapshot().revision)
        assertEquals(store.snapshot().revision, open(disk).snapshot().revision)
    }

    @Test fun anEarlierSnapshotStaysUnchangedAndCannotBeChanged() {
        val store = open(disk())
        val before = store.snapshot()
        val phases = before.entries.map { it.phase }
        store.remove(before.entries.first().enrollment.recordID.copyBytes(), before.revision)
        assertEquals(phases, before.entries.map { it.phase })
        assertFails { (before.entries as MutableList).clear() }
        assertFails { (before.entries.subList(0, 1) as MutableList).clear() }
        assertFails { (before.entries.iterator() as MutableIterator).remove() }
        assertEquals(phases.size, before.entries.size)
    }
}
