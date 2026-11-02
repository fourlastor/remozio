package dev.remozio.android.audit

import androidx.compose.ui.input.key.Key
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.espresso.Espresso
import dev.remozio.android.MainActivity
import dev.remozio.android.R
import dev.remozio.android.RemozioApplication
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class AuditWorkSettingsInteractionTest {
    @get:Rule val ui = createAndroidComposeRule<MainActivity>()
    private var original: AuditWorkPolicy? = null
    private val settings get() = (ui.activity.application as RemozioApplication).auditWorkSettings

    @After fun restoreSavedPolicy() {
        original?.let { check(settings.save(it)) }
    }

    @Test fun productionSettingsValidateSaveAndRestoreTheDraft() {
        check(ui.activity.packageName == "dev.remozio.android.debug")
        ui.runOnIdle {
            original = settings.read()
            check(settings.save(AuditWorkPolicy()))
        }
        ui.onNodeWithText(text(R.string.nav_settings)).performClick()
        ui.onNodeWithText(text(R.string.audit_settings_show)).performScrollTo().performClick()

        field(R.string.audit_settings_responses).performScrollTo().performTextReplacement("0")
        field(R.string.audit_settings_seconds).performScrollTo().performTextReplacement("61")
        saveButton().performScrollTo().assertIsNotEnabled()
        assertEquals(AuditWorkPolicy(), AuditWorkSettings(ui.activity).read())

        field(R.string.audit_settings_responses).performScrollTo().performTextReplacement("1")
        field(R.string.audit_settings_responses).performClick().assertIsFocused()
        field(R.string.audit_settings_responses).performKeyInput { pressKey(Key.Tab) }
        field(R.string.audit_settings_seconds).assertIsFocused().performTextReplacement("1")
        Espresso.closeSoftKeyboard()
        save(AuditWorkPolicy(1, 1))
        assertSavedValues("1 response", "1 second")
        assertEquals(AuditWorkPolicy(1, 1), AuditWorkSettings(ui.activity).read())

        field(R.string.audit_settings_responses).performScrollTo().performTextReplacement("2")
        field(R.string.audit_settings_seconds).performScrollTo().performTextReplacement("3")
        assertEquals(AuditWorkPolicy(1, 1), AuditWorkSettings(ui.activity).read())
        ui.activityRule.scenario.recreate()
        ui.waitForIdle()
        field(R.string.audit_settings_responses).performScrollTo().assert(hasEditableText("2"))
        field(R.string.audit_settings_seconds).performScrollTo().assert(hasEditableText("3"))
        save(AuditWorkPolicy(2, 3))
        assertSavedValues("2 responses", "3 seconds")

        ui.onNodeWithText(text(R.string.wake_settings_defaults)).performScrollTo().performClick()
        field(R.string.audit_settings_responses).performScrollTo().assert(hasEditableText("32"))
        field(R.string.audit_settings_seconds).performScrollTo().assert(hasEditableText("30"))
        assertEquals(AuditWorkPolicy(2, 3), AuditWorkSettings(ui.activity).read())
        save(AuditWorkPolicy())
        assertSavedValues("32 responses", "30 seconds")
        assertEquals(AuditWorkPolicy(), AuditWorkSettings(ui.activity).read())
        ui.activityRule.scenario.recreate()
        ui.waitForIdle()
        assertSavedValues("32 responses", "30 seconds")
    }

    private fun text(id: Int) = ui.activity.getString(id)
    private fun field(id: Int) = ui.onNode(hasSetTextAction() and hasText(text(id)))
    private fun saveButton() = ui.onNodeWithText(text(R.string.audit_settings_save))
    private fun hasEditableText(value: String) = SemanticsMatcher.expectValue(
        SemanticsProperties.EditableText, androidx.compose.ui.text.AnnotatedString(value),
    )
    private fun save(policy: AuditWorkPolicy) {
        val button = saveButton().performScrollTo().assertIsEnabled()
        with(button.getUnclippedBoundsInRoot()) {
            check(width.value >= 48f && height.value >= 48f)
        }
        button.performClick()
        ui.waitUntil(5_000) { settings.read() == policy }
        ui.onNodeWithText(text(R.string.audit_settings_saved)).performScrollTo().assertIsDisplayed()
    }
    private fun assertSavedValues(responses: String, seconds: String) {
        ui.onNodeWithText(ui.activity.getString(R.string.audit_settings_saved_values, responses, seconds))
            .performScrollTo().assertIsDisplayed()
    }
}
