package dev.remozio.android.audit

import android.app.Activity
import android.graphics.Rect
import android.util.Log
import android.view.accessibility.AccessibilityNodeInfo
import androidx.activity.ComponentActivity
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import androidx.test.espresso.Espresso
import androidx.test.platform.app.InstrumentationRegistry
import dev.remozio.android.R
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class CompactAuditDetailsInteractionTest : AuditDetailsInteractionChecks<AuditPreviewActivity>(AuditPreviewActivity::class.java)
class ExpandedAuditDetailsInteractionTest : AuditDetailsInteractionChecks<AuditExpandedPreviewActivity>(AuditExpandedPreviewActivity::class.java)

abstract class AuditDetailsInteractionChecks<A : ComponentActivity>(activityClass: Class<A>) {
    @get:Rule val ui = createAndroidComposeRule(activityClass)

    @Test fun closeAndSystemBackRestoreTheSharedAuditList() {
        val details = ui.activity.getString(R.string.audit_event_details)
        val title = ui.activity.getString(R.string.audit_details)
        val close = ui.activity.getString(R.string.audit_close)
        fun card() = ui.onAllNodes(hasText(details) and hasClickAction()).onFirst()
        ui.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(details))
        ui.onRoot().performKeyInput { pressKey(Key.Tab) }
        card().performSemanticsAction(SemanticsActions.RequestFocus) { assertTrue(it()) }
        card().assertIsFocused().performKeyInput { pressKey(Key.Enter) }
        ui.onNodeWithText(title).assertIsDisplayed()
        val opened = NativeAccessibilityFrames.capture(ui.activity, "details-open")
        assertTrue(opened.any { title in it.labels && it.heading })
        assertTrue(opened.any { it.ownsLabel(close, opened) && it.clickable && it.enabled })
        assertTrue(opened.indexOfFirst { title in it.labels } < opened.indexOfFirst { it.ownsLabel(close, opened) && it.clickable })

        ui.onNodeWithText(close).performSemanticsAction(SemanticsActions.RequestFocus) { assertTrue(it()) }
        ui.onNodeWithText(close).performKeyInput { pressKey(Key.Enter) }
        ui.onNodeWithText(title).assertDoesNotExist()
        card().assertIsDisplayed().assertIsFocused()
        val closed = NativeAccessibilityFrames.capture(ui.activity, "details-closed")
        assertTrue(closed.none { title in it.labels })

        card().performKeyInput { pressKey(Key.Enter) }
        ui.onNodeWithText(title).assertIsDisplayed()
        Espresso.pressBack()
        ui.onNodeWithText(title).assertDoesNotExist()
        card().assertIsDisplayed().assertIsFocused()
        assertTrue(ui.activityRule.scenario.state == Lifecycle.State.RESUMED)
        NativeAccessibilityFrames.capture(ui.activity, "details-back")
    }
}

internal data class NativeAccessibilityNode(
    val path: String, val role: String, val labels: List<String>, val editable: Boolean, val enabled: Boolean,
    val clickable: Boolean, val heading: Boolean, val error: String?,
) {
    fun ownsLabel(label: String, nodes: List<NativeAccessibilityNode>) = nodes.any {
        label in it.labels && (it.path == path || it.path.startsWith("$path/"))
    }
}

internal object NativeAccessibilityFrames {
    fun capture(activity: Activity, scene: String): List<NativeAccessibilityNode> {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.waitForIdle(100, 5_000)
        val root = checkNotNull(automation.rootInActiveWindow)
        check(root.packageName?.toString() == "dev.remozio.android.debug")
        val frame = System.currentTimeMillis().toString() + "-" + scene
        val window = activity.windowManager.currentWindowMetrics.bounds
        val metrics = activity.resources.displayMetrics
        val header = JSONObject().put("schema", 1).put("frame", frame).put("scene", scene)
            .put("activity", activity.javaClass.name).put("widthPixels", window.width()).put("heightPixels", window.height())
            .put("density", metrics.density).put("fontScale", activity.resources.configuration.fontScale)
        Log.i("RemozioAuditA11y", JSONObject(header.toString()).put("kind", "begin").toString())
        val pending = ArrayDeque<Pair<AccessibilityNodeInfo, String>>()
        pending.add(root to "0")
        val nodes = mutableListOf<NativeAccessibilityNode>()
        while (pending.isNotEmpty()) {
            check(nodes.size < 512)
            val (node, path) = pending.removeFirst()
            val labels = listOfNotNull(node.text?.toString(), node.contentDescription?.toString(), node.hintText?.toString())
                .filter(String::isNotBlank).distinct()
            nodes += NativeAccessibilityNode(path, node.className.toString(), labels, node.isEditable, node.isEnabled,
                node.isClickable, node.isHeading, node.error?.toString())
            val bounds = Rect().also(node::getBoundsInScreen)
            Log.i("RemozioAuditA11y", JSONObject().put("schema", 1).put("frame", frame).put("kind", "node")
                .put("path", path).put("class", node.className).put("labels", JSONArray(labels.map { it.take(256) }))
                .put("editable", node.isEditable).put("enabled", node.isEnabled).put("clickable", node.isClickable)
                .put("heading", node.isHeading).put("keyboardFocused", node.isFocused)
                .put("accessibilityFocused", node.isAccessibilityFocused).put("visible", node.isVisibleToUser)
                .put("error", node.error).put("windowId", node.windowId).put("bounds", bounds.toShortString()).toString())
            for (index in 0 until node.childCount) node.getChild(index)?.let { pending.add(it to "$path/$index") }
        }
        Log.i("RemozioAuditA11y", JSONObject(header.toString()).put("kind", "end").put("nodes", nodes.size).toString())
        return nodes
    }
}
