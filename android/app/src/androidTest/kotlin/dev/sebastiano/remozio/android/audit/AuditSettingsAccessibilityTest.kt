package dev.sebastiano.remozio.android.audit

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import androidx.test.espresso.Espresso
import dev.sebastiano.remozio.android.MainActivity
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.RemozioApplication
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class AuditSettingsAccessibilityTest {
    @get:Rule val ui = createAndroidComposeRule<MainActivity>()

    @Test fun nativeNodesExposeInvalidInputAndBackKeepsTheSavedPolicy() {
        val activity = ui.activity
        val app = activity.application as RemozioApplication
        val original = app.auditWorkSettings.read()
        fun text(id: Int) = activity.getString(id)
        fun field(id: Int) = ui.onNode(hasSetTextAction() and hasText(text(id)))
        ui.onNodeWithText(text(R.string.nav_settings)).performClick()
        ui.onNodeWithText(text(R.string.audit_settings_show)).performScrollTo().performClick()
        field(R.string.audit_settings_responses).performScrollTo().performTextReplacement("0")
        Espresso.closeSoftKeyboard()
        val responseNodes = NativeAccessibilityFrames.capture(activity, "settings-invalid-response")
        assertTrue(responseNodes.any { it.editable && it.ownsLabel(text(R.string.audit_settings_responses), responseNodes) && it.error != null })
        field(R.string.audit_settings_seconds).performScrollTo().performTextReplacement("61")
        Espresso.closeSoftKeyboard()
        val timeoutNodes = NativeAccessibilityFrames.capture(activity, "settings-invalid-timeout")
        assertTrue(timeoutNodes.any { it.editable && it.ownsLabel(text(R.string.audit_settings_seconds), timeoutNodes) && it.error != null })
        ui.onNodeWithText(text(R.string.audit_settings_save)).performScrollTo().assertIsDisplayed().assertIsNotEnabled()
        val saveNodes = NativeAccessibilityFrames.capture(activity, "settings-invalid-save")
        assertTrue("The disabled Save action must own its label and button role: $saveNodes", saveNodes.any { action ->
            action.clickable && !action.enabled && action.ownsLabel(text(R.string.audit_settings_save), saveNodes) &&
                saveNodes.any { it.role == "android.widget.Button" && (it.path == action.path || it.path.startsWith("${action.path}/")) }
        })
        assertEquals(original, AuditWorkSettings(activity).read())
        Espresso.pressBackUnconditionally()
        ui.waitUntil(5_000) { ui.activityRule.scenario.state != Lifecycle.State.RESUMED }
        assertEquals(original, AuditWorkSettings(app).read())
    }
}
