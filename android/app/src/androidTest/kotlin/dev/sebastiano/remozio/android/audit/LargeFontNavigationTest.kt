package dev.sebastiano.remozio.android.audit

import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.TextLayoutResult
import dev.sebastiano.remozio.android.R
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class LargeFontNavigationTest {
    @get:Rule val ui = createAndroidComposeRule<AuditLargeFontPreviewActivity>()

    /** Each label stays inside its target, and a label that wraps breaks only between words (#494). */
    @Test fun everyNavigationLabelFitsItsSelectableTargetAtTwiceTheFontScale() {
        val failures = mutableListOf<String>()
        for (id in listOf(R.string.nav_requests, R.string.nav_macs, R.string.nav_audit, R.string.nav_settings)) {
            val text = ui.activity.getString(id)
            val label = ui.onNodeWithText(text, useUnmergedTree = true).assertIsDisplayed()
            val layouts = mutableListOf<TextLayoutResult>()
            label.performSemanticsAction(SemanticsActions.GetTextLayoutResult) { check(it(layouts)) }
            val layout = layouts.single()
            val bounds = label.fetchSemanticsNode().boundsInRoot
            val target = ui.onNode(hasText(text) and isSelectable()).fetchSemanticsNode().boundsInRoot
            val lineLeft = (0 until layout.lineCount).minOf(layout::getLineLeft)
            val lineRight = (0 until layout.lineCount).maxOf(layout::getLineRight)
            val widthOverflow = lineRight - layout.size.width
            val heightOverflow = layout.getLineBottom(layout.lineCount - 1) - layout.size.height
            val wordBreaks = (0 until layout.lineCount - 1).count { !text[layout.getLineEnd(it) - 1].isWhitespace() }
            val geometry = "$text: lineLeft=$lineLeft, lineRight=$lineRight, textWidth=${layout.size.width}, " +
                "widthOverflow=$widthOverflow, heightOverflow=$heightOverflow, wordBreaks=$wordBreaks, " +
                "constraints=${layout.layoutInput.constraints}, lines=${layout.lineCount}, " +
                "bounds=$bounds, target=$target, fontScale=${label.fetchSemanticsNode().layoutInfo.density.fontScale}"
            android.util.Log.i("RemozioNavGeometry", geometry)
            if (lineLeft < -1f || widthOverflow > 1f || heightOverflow > 1f || wordBreaks > 0 || bounds.height + 1 < layout.size.height ||
                bounds.left < target.left - 1 || bounds.top < target.top - 1 ||
                bounds.right > target.right + 1 || bounds.bottom > target.bottom + 1) {
                failures += geometry
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }
}
