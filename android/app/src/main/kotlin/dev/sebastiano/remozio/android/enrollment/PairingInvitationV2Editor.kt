package dev.sebastiano.remozio.android.enrollment

import android.content.ClipboardManager
import android.content.Context
import android.text.InputType
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.core.widget.doAfterTextChanged
import dev.remozio.protocol.PairingInvitationV2
import dev.sebastiano.remozio.android.R

/** Treat pasted pairing text as a credential even before it decodes. */
internal class PairingInvitationV2Editor(context: Context, private val onInvitation: (PairingInvitationV2?) -> Unit) : EditText(context) {
    init {
        isSaveEnabled = false
        isSaveFromParentEnabled = false
        importantForAutofill = IMPORTANT_FOR_AUTOFILL_NO
        importantForContentCapture = IMPORTANT_FOR_CONTENT_CAPTURE_NO
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        hint = context.getString(R.string.pairing_setup_invitation)
        var clearing = false
        doAfterTextChanged { value ->
            if (clearing || value == null) return@doAfterTextChanged
            val oversized = value.length > MAXIMUM_TEXT
            val invitation = if (oversized) null else parse(value)
            if (invitation != null || oversized) {
                clearing = true
                try { value.clear() } finally { clearing = false }
            }
            onInvitation(invitation)
        }
    }

    // Import from the clipboard. This view never exports invitation text to it.
    override fun onTextContextMenuItem(id: Int): Boolean = when (id) {
        android.R.id.cut, android.R.id.copy, android.R.id.shareText -> true
        android.R.id.paste, android.R.id.pasteAsPlainText -> pasteInvitation() || super.onTextContextMenuItem(id)
        else -> super.onTextContextMenuItem(id)
    }

    private fun pasteInvitation(): Boolean {
        val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return false
        val raw = clipboard.invitationText() ?: return false
        val pasted = parse(raw) ?: return false
        text?.clear()
        onInvitation(pasted)
        if (clipboard.invitationText() == raw) clipboard.clearPrimaryClip()
        return true
    }

    private fun ClipboardManager.invitationText(): String? = primaryClip
        ?.takeIf { it.itemCount == 1 }?.getItemAt(0)?.text?.takeIf { it.length <= MAXIMUM_TEXT }?.toString()

    private fun parse(value: CharSequence): PairingInvitationV2? =
        value.takeIf { it.isNotEmpty() }?.toString()?.trim()?.let {
            runCatching { PairingInvitationV2.importText(it) }.getOrNull()
        }

    private companion object {
        const val MAXIMUM_TEXT = 1043
    }
}
