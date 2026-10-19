package dev.remozio.protocol

internal class ActionWireException : IllegalArgumentException("Invalid action encoding")

internal object ActionWire {
    private val choices = mapOf(
        0uL to ActionChoice.DECLINE, 1uL to ActionChoice.CANCEL_TARGET, 2uL to ActionChoice.EXECUTE,
        3uL to ActionChoice.APPROVE_ACCESS, 4uL to ActionChoice.UNLOCK_VAULT,
        5uL to ActionChoice.ALLOW_ONCE, 6uL to ActionChoice.DENY_ONCE,
        7uL to ActionChoice.ALLOW_RULE, 8uL to ActionChoice.DENY_RULE, 9uL to ActionChoice.REMOVE_RULE,
    )

    fun encode(action: CapturedAction): CborValue {
        val fields = mutableMapOf<ULong, CborValue>(0uL to CborValue.Unsigned(choices.entries.single { it.value == action.choice }.key))
        val tag = when (val scope = action.scope) {
            ActionScope.CurrentRequest -> 0uL
            ActionScope.Session -> 1uL
            is ActionScope.Timed -> { fields[2u] = CborValue.Unsigned(scope.seconds); 2uL }
            ActionScope.Forever -> 3uL
        }
        fields[1u] = CborValue.Unsigned(tag)
        return CborValue.Fields(fields)
    }

    fun decode(value: CborValue): CapturedAction {
        val fields = (value as? CborValue.Fields)?.values ?: fail()
        val choice = choices[(fields[0u] as? CborValue.Unsigned)?.value] ?: fail()
        val tag = (fields[1u] as? CborValue.Unsigned)?.value ?: fail()
        val scope = when (tag) {
            0uL -> ActionScope.CurrentRequest
            1uL -> ActionScope.Session
            2uL -> {
                val seconds = (fields[2u] as? CborValue.Unsigned)?.value ?: fail()
                ensure(seconds > 0uL)
                ActionScope.Timed(seconds)
            }
            3uL -> ActionScope.Forever
            else -> fail()
        }
        ensure(fields.keys == if (tag == 2uL) setOf(0uL, 1uL, 2uL) else setOf(0uL, 1uL))
        return CapturedAction(choice, scope)
    }

    private fun ensure(condition: Boolean) { if (!condition) fail() }
    private fun fail(): Nothing = throw ActionWireException()
}
