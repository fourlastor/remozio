package dev.sebastiano.remozio.android

import org.junit.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProbeOperationTest {
    private class AuthenticationRequired : Exception()

    @Test fun recognizesOnlyTypedAuthenticationCauses() {
        fun denied(error: Throwable) = hasAuthenticationCause(error) { it is AuthenticationRequired }
        assertTrue(denied(AuthenticationRequired()))
        assertTrue(denied(java.security.SignatureException(AuthenticationRequired())))
        assertTrue(denied(java.security.SignatureException(java.security.SignatureException(AuthenticationRequired()))))
        assertFalse(denied(java.security.SignatureException("Authentication required")))
        assertFalse(denied(java.security.SignatureException(java.security.InvalidKeyException())))
        val first = Exception()
        val second = Exception(first)
        first.initCause(second)
        assertFalse(denied(first))
        var deep: Throwable = AuthenticationRequired()
        repeat(16) { deep = Exception(deep) }
        assertFalse(denied(deep))
    }

    @Test fun stoppedOperationCannotCompleteOrOwnReplacement() {
        val gate = ProbeOperation()
        val stopped = gate.begin()
        gate.invalidate()
        assertFalse(gate.complete(stopped))
        val replacement = gate.begin()
        assertFalse(gate.owns(stopped))
        assertFalse(gate.complete(stopped))
        assertTrue(gate.complete(replacement))
        assertFalse(gate.complete(replacement))
    }
    @Test fun newOperationInvalidatesPriorCallback() {
        val gate = ProbeOperation()
        val old = gate.begin()
        val current = gate.begin()
        assertFalse(gate.complete(old))
        assertTrue(gate.owns(current))
    }
}
