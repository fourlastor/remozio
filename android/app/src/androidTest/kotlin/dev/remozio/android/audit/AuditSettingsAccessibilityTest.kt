package dev.remozio.android.audit

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import androidx.test.espresso.Espresso
import dev.remozio.android.MainActivity
import dev.remozio.android.R
import dev.remozio.android.RemozioApplication
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
        assertTrue(responseNodes.any { it.editable && text(R.string.audit_settings_responses) in it.labels && it.error != null })
        field(R.string.audit_settings_seconds).performScrollTo().performTextReplacement("61")
        Espresso.closeSoftKeyboard()
        val timeoutNodes = NativeAccessibilityFrames.capture(activity, "settings-invalid-timeout")
        assertTrue(timeoutNodes.any { it.editable && text(R.string.audit_settings_seconds) in it.labels && it.error != null })
        ui.onNodeWithText(text(R.string.audit_settings_save)).performScrollTo().assertIsNotEnabled()
        val saveNodes = NativeAccessibilityFrames.capture(activity, "settings-invalid-save")
        assertTrue(saveNodes.any { text(R.string.audit_settings_save) in it.labels && !it.enabled })
        assertEquals(original, AuditWorkSettings(activity).read())
        Espresso.pressBackUnconditionally()
        ui.waitUntil(5_000) { ui.activityRule.scenario.state != Lifecycle.State.RESUMED }
        assertEquals(original, AuditWorkSettings(app).read())
    }
}
