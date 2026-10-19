package dev.remozio.protocol

import java.io.File
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class ActionPolicyTest {
    @Test
    fun sharedActionPolicyVectors() {
        val vectors = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.actionVectors"))).readText()).jsonArray
        assertTrue(vectors.size > 40)
        for (vector in vectors) {
            val fields = vector.jsonObject
            fun text(key: String) = fields.getValue(key).jsonPrimitive.content
            val name = text("name")
            val kind = RequestKind.valueOf(enumName(text("kind")))
            val choice = ActionChoice.valueOf(enumName(text("choice")))
            val scope = when (text("scope")) {
                "currentRequest" -> ActionScope.CurrentRequest
                "session" -> ActionScope.Session
                "forever" -> ActionScope.Forever
                "timed" -> ActionScope.Timed(text("seconds").toULong())
                else -> error("Unknown scope fixture")
            }
            val action = CapturedAction(choice, scope)
            val retained = if (fields.getValue("permitted").jsonPrimitive.boolean) setOf(action) else emptySet()
            if ("error" in fields) {
                val error = assertFailsWith<ActionPolicyException>(name) { ActionPolicy.requirement(action, kind, retained) }
                assertEquals(enumName(text("error")), error.reason.name, name)
            } else {
                val result = ActionPolicy.requirement(action, kind, retained)
                assertEquals(enumName(text("key")), result.keyClass.name, name)
                assertEquals(enumName(text("purpose")), result.purpose.name, name)
                assertEquals(enumName(text("effect")), result.effect.name, name)
            }
        }
    }

    @Test
    fun scopeChangeDoesNotMatchRetainedChoice() {
        val retained = CapturedAction(ActionChoice.ALLOW_RULE, ActionScope.Timed(60u))
        val altered = CapturedAction(ActionChoice.ALLOW_RULE, ActionScope.Timed(61u))
        val error = assertFailsWith<ActionPolicyException> {
            ActionPolicy.requirement(altered, RequestKind.LITTLE_SNITCH, setOf(retained))
        }
        assertEquals(ActionPolicyFailure.NOT_PERMITTED, error.reason)
    }

    private fun enumName(value: String): String = value.replace(Regex("([a-z])([A-Z])"), "$1_$2").uppercase(Locale.ROOT)
}
