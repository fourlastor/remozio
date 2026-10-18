package dev.remozio.android.push

import dev.remozio.protocol.CborValue

/** One collector remembers confirmed admissions until its finite sweep completes. */
internal class PushRegistrationWorkSweep {
    private val visited = mutableSetOf<CborValue.Bytes>()

    fun pending(records: List<CborValue.Bytes>): List<CborValue.Bytes> {
        visited.retainAll(records.toSet())
        return records.filter { it !in visited }
    }

    fun admitted(record: CborValue.Bytes) { visited += record }
    fun reset() { visited.clear() }
}
