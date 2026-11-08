package dev.remozio.pairing

import kotlinx.coroutines.*
import kotlinx.io.IOException
import kotlin.test.*

class PairingTransportStreamTest {
    /** Records calls. The test fires the events by hand, as the platform would. */
    private class Fake : PairingTransport {
        var events: PairingTransportEvents? = null
        var starts = 0; var requests = 0; var cancels = 0
        val sent = mutableListOf<ByteArray>()
        val completions = mutableListOf<PairingSendCompletion>()
        override fun start(events: PairingTransportEvents) { starts++; this.events = events }
        override fun requestBytes() { requests++ }
        override fun send(bytes: ByteArray, completion: PairingSendCompletion) { sent += bytes; completions += completion }
        override fun cancel() { cancels++ }
    }

    // A failing async child must not cancel the test: each case awaits its failures itself.
    private fun test(body: suspend CoroutineScope.() -> Unit) = runBlocking { supervisorScope { body() } }

    private suspend fun opened(fake: Fake, stream: PairingTransportStream, scope: CoroutineScope) {
        val open = scope.async { stream.awaitOpen() }
        yield(); fake.events!!.opened(); open.await()
    }

    @Test fun opensOnlyAfterTheOpenedEvent() = test {
        val fake = Fake(); val stream = PairingTransportStream(fake)
        val open = async { stream.awaitOpen() }
        yield()
        assertEquals(1, fake.starts)
        assertFalse(open.isCompleted)
        fake.events!!.opened(); open.await()
    }

    @Test fun closedBeforeOpenedFailsTheOpen() = test {
        val fake = Fake(); val stream = PairingTransportStream(fake)
        val open = async { stream.awaitOpen() }
        yield(); fake.events!!.closed("pin mismatch")
        assertFailsWith<IOException> { open.await() }
        withTimeout(1_000) { stream.awaitClosed() }
        // A late opened event changes nothing.
        fake.events!!.opened()
    }

    @Test fun requestsOneDeliveryAtATimeAndSplitsLargeOnes() = test {
        val fake = Fake(); val stream = PairingTransportStream(fake)
        opened(fake, stream, this)
        val first = async { stream.receive() }
        yield()
        assertEquals(1, fake.requests)
        fake.events!!.received(ByteArray(PairingTransport.MAXIMUM_DELIVERY) { it.toByte() })
        val a = first.await()!!; val b = stream.receive()!!
        assertEquals(32_768, a.size); assertEquals(32_768, b.size)
        assertEquals(0.toByte(), a[0]); assertEquals(0.toByte(), b[0]); assertEquals(1, fake.requests)
        val next = async { stream.receive() }
        yield(); assertEquals(2, fake.requests)
        fake.events!!.received(byteArrayOf(7)); assertContentEquals(byteArrayOf(7), next.await())
    }

    @Test fun anEmptyOrOversizedDeliveryFailsAndCancels() = test {
        for (size in listOf(0, PairingTransport.MAXIMUM_DELIVERY + 1)) {
            val fake = Fake(); val stream = PairingTransportStream(fake)
            opened(fake, stream, this)
            val read = async { stream.receive() }
            yield(); fake.events!!.received(ByteArray(size))
            assertFailsWith<IOException> { read.await() }
            assertEquals(1, fake.cancels)
        }
    }

    @Test fun orderlyCloseIsEndOfStreamAndAnErrorIsAFailure() = test {
        val fake = Fake(); val stream = PairingTransportStream(fake)
        opened(fake, stream, this)
        val read = async { stream.receive() }
        yield(); fake.events!!.received(byteArrayOf(1, 2)); fake.events!!.closed(null)
        assertContentEquals(byteArrayOf(1, 2), read.await())
        assertNull(stream.receive())
        // Bytes after closed are ignored.
        fake.events!!.received(byteArrayOf(3)); assertNull(stream.receive())

        val failing = Fake(); val other = PairingTransportStream(failing)
        opened(failing, other, this)
        val failed = async { other.receive() }
        yield(); failing.events!!.closed("reset")
        assertFailsWith<IOException> { failed.await() }
    }

    @Test fun sendWaitsForItsCompletion() = test {
        val fake = Fake(); val stream = PairingTransportStream(fake)
        opened(fake, stream, this)
        val ok = async { stream.send(byteArrayOf(1)) }
        yield(); assertFalse(ok.isCompleted)
        fake.completions.single().done(null); ok.await()
        val bad = async { stream.send(byteArrayOf(2)) }
        yield(); fake.completions[1].done("broken")
        assertFailsWith<IOException> { bad.await() }
        val lost = async { stream.send(byteArrayOf(3)) }
        yield(); fake.events!!.closed(null)
        assertFailsWith<IOException> { lost.await() }
        assertFailsWith<IOException> { stream.send(byteArrayOf(4)) }
        assertEquals(3, fake.sent.size)
    }

    @Test fun theSentBytesAreACopy() = test {
        val fake = Fake(); val stream = PairingTransportStream(fake)
        opened(fake, stream, this)
        val bytes = byteArrayOf(5)
        val send = async { stream.send(bytes) }
        yield(); bytes[0] = 9
        assertContentEquals(byteArrayOf(5), fake.sent.single())
        fake.completions.single().done(null); send.await()
    }

    @Test fun closeBeforeStartNeverStartsTheTransport() = test {
        val fake = Fake(); val stream = PairingTransportStream(fake)
        stream.close()
        withTimeout(1_000) { stream.awaitClosed() }
        assertFailsWith<IOException> { stream.awaitOpen() }
        assertEquals(0, fake.starts); assertEquals(0, fake.cancels)
    }

    @Test fun closeAfterStartCancelsOnceAndWaitsForClosed() = test {
        val fake = Fake(); val stream = PairingTransportStream(fake)
        val open = async { stream.awaitOpen() }
        yield()
        stream.close(); stream.close()
        assertEquals(1, fake.cancels)
        val waiting = async { stream.awaitClosed() }
        yield(); assertFalse(waiting.isCompleted)
        fake.events!!.closed("cancelled")
        withTimeout(1_000) { waiting.await() }
        assertFailsWith<IOException> { open.await() }
    }

    @Test fun cancellingAWaitingOpenLeavesTheCleanupToClose() = test {
        val fake = Fake(); val stream = PairingTransportStream(fake)
        val open = async { stream.awaitOpen() }
        yield(); open.cancelAndJoin()
        stream.close()
        assertEquals(1, fake.cancels)
        fake.events!!.closed(null)
        withTimeout(1_000) { stream.awaitClosed() }
    }
}
