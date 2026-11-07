package dev.sebastiano.remozio.android

import androidx.annotation.PluralsRes
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource

internal enum class ElapsedUnit { UNDER_MINUTE, MINUTES, HOURS, DAYS }

/** An age in whole minutes, hours or days. Its text changes at most once a minute. */
internal data class CoarseElapsed(val unit: ElapsedUnit, val amount: Long)

internal fun coarseElapsed(milliseconds: ULong): CoarseElapsed {
    val minutes = milliseconds / 60_000uL
    return when {
        minutes >= 1440uL -> CoarseElapsed(ElapsedUnit.DAYS, (minutes / 1440uL).toLong())
        minutes >= 60uL -> CoarseElapsed(ElapsedUnit.HOURS, (minutes / 60uL).toLong())
        minutes >= 1uL -> CoarseElapsed(ElapsedUnit.MINUTES, minutes.toLong())
        else -> CoarseElapsed(ElapsedUnit.UNDER_MINUTE, 0)
    }
}

/** One sentence per unit, so each language can phrase the whole sentence with its own plurals. */
internal class CoarseElapsedText(
    @param:StringRes val underMinute: Int,
    @param:PluralsRes val minutes: Int,
    @param:PluralsRes val hours: Int,
    @param:PluralsRes val days: Int,
)

@Composable
internal fun coarseElapsedText(milliseconds: ULong, text: CoarseElapsedText): String {
    val age = coarseElapsed(milliseconds)
    val plural = when (age.unit) {
        ElapsedUnit.UNDER_MINUTE -> return stringResource(text.underMinute)
        ElapsedUnit.MINUTES -> text.minutes
        ElapsedUnit.HOURS -> text.hours
        ElapsedUnit.DAYS -> text.days
    }
    return pluralStringResource(plural, age.amount.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), age.amount)
}
