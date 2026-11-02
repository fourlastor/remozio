package dev.sebastiano.remozio.android.transport

import org.junit.Test
import kotlin.test.*

class TransportKeyCreationTest {
    private val alias = "remozio.transport.v1.${"a".repeat(32)}"
    private val validity = TransportCertificateValidity(10, 100)
    private class Backend : TransportKeyCreationBackend {
        var present = false
        val calls = mutableListOf<Boolean>()
        var fail: (() -> Unit)? = null
        override fun contains(alias: String) = present
        override fun generate(alias: String, strongBox: Boolean, validity: TransportCertificateValidity): ByteArray {
            calls += strongBox
            fail?.invoke()
            present = true
            return byteArrayOf(1, 2, 3)
        }
    }

    @Test fun existingAliasesAndInvalidNamesNeverReachGeneration() {
        val backend = Backend().apply { present = true }
        assertFailsWith<IllegalStateException> { createTransportKey(backend, alias, validity) }
        backend.present = false
        assertFailsWith<IllegalArgumentException> { createTransportKey(backend, "remozio.approval.v1.${"a".repeat(32)}", validity) }
        assertTrue(backend.calls.isEmpty())
    }

    @Test fun triesStrongBoxFirstAndFallsBackOnlyAfterExplicitUnavailability() {
        val backend = Backend()
        assertContentEquals(byteArrayOf(1, 2, 3), createTransportKey(backend, alias, validity))
        assertEquals(listOf(true), backend.calls)
        val fallback = Backend()
        fallback.fail = { fallback.fail = null; throw StrongBoxNotAvailable() }
        assertContentEquals(byteArrayOf(1, 2, 3), createTransportKey(fallback, alias, validity))
        assertEquals(listOf(true, false), fallback.calls)
    }

    @Test fun partialStrongBoxCreationAndOtherFailuresNeverTriggerReplacement() {
        val partial = Backend()
        partial.fail = { partial.present = true; throw StrongBoxNotAvailable() }
        assertFailsWith<IllegalStateException> { createTransportKey(partial, alias, validity) }
        assertEquals(listOf(true), partial.calls)
        assertTrue(partial.present)
        val other = Backend().apply { fail = { throw java.security.ProviderException("synthetic") } }
        assertFailsWith<java.security.ProviderException> { createTransportKey(other, alias, validity) }
        assertEquals(listOf(true), other.calls)
    }

    @Test fun fallbackFailureIsNotRetried() {
        val backend = Backend().apply { fail = { throw StrongBoxNotAvailable() } }
        assertFailsWith<StrongBoxNotAvailable> { createTransportKey(backend, alias, validity) }
        assertEquals(listOf(true, false), backend.calls)
    }

    @Test fun certificateWindowMustIncludeCreationTime() {
        validity.validateAt(10)
        validity.validateAt(99)
        assertFailsWith<IllegalArgumentException> { validity.validateAt(9) }
        assertFailsWith<IllegalArgumentException> { validity.validateAt(100) }
        assertFailsWith<IllegalArgumentException> { TransportCertificateValidity(20, 10).validateAt(15) }
    }
}
