package dev.remozio.protocol

import java.io.File
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

class RequestLifecycleTest {
    @Test
    fun completeTransitionMatrix() {
        val rows = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.lifecycleVectors"))).readText()).jsonArray
        assertEquals(21, rows.size)
        val expected = mutableMapOf<Pair<RequestPhase, RequestEvent>, RequestPhase>()
        for (row in rows) {
            val cells = row.jsonArray
            assertEquals(3, cells.size)
            val phase = RequestPhase.valueOf(enumName(cells[0].jsonPrimitive.content))
            val event = RequestEvent.valueOf(enumName(cells[1].jsonPrimitive.content))
            val result = RequestPhase.valueOf(enumName(cells[2].jsonPrimitive.content))
            assertNull(expected.put(phase to event, result))
        }
        for (phase in RequestPhase.entries) {
            for (event in RequestEvent.entries) {
                val result = expected[phase to event]
                val label = "$phase:$event"
                if (result != null) {
                    assertEquals(result, RequestLifecycle.transition(phase, event), label)
                } else {
                    val error = assertFailsWith<LifecycleException>(label) { RequestLifecycle.transition(phase, event) }
                    assertEquals(if (phase.isTerminal) LifecycleFailure.TERMINAL else LifecycleFailure.INVALID_TRANSITION, error.reason, label)
                }
            }
        }
    }

    @Test
    fun competingDecisionCannotReplaceFirstAcceptedDecision() {
        val accepted = RequestLifecycle.transition(RequestPhase.PRESENTED, RequestEvent.AUTHORIZE)
        for (other in listOf(RequestEvent.AUTHORIZE, RequestEvent.DECLINE, RequestEvent.CANCEL, RequestEvent.EXPIRE)) {
            assertFailsWith<LifecycleException> { RequestLifecycle.transition(accepted, other) }
        }
        assertEquals(RequestPhase.EXECUTING, RequestLifecycle.transition(accepted, RequestEvent.BEGIN_DISPATCH))
    }

    @Test
    fun unknownCannotBeRetriedOrTurnedIntoSuccessByLateAcknowledgment() {
        val interrupted = RequestLifecycle.transition(RequestPhase.EXECUTING, RequestEvent.RESTART_AUTHORITY)
        assertEquals(RequestPhase.UNKNOWN, interrupted)
        for (event in RequestEvent.entries) {
            assertFailsWith<LifecycleException> { RequestLifecycle.transition(interrupted, event) }
        }
    }

    private fun enumName(value: String): String = value.replace(Regex("([a-z])([A-Z])"), "$1_$2").uppercase(Locale.ROOT)
}
