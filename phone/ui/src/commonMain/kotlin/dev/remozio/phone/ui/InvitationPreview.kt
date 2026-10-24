package dev.remozio.phone.ui

import dev.remozio.protocol.PairingInvitation

/** What the Add computer screen shows. Nothing here authenticates the computer or stores the invitation. */
sealed interface InvitationPreview {
    data class Parsed(val macID: String, val accountID: String, val label: String, val fingerprint: String) : InvitationPreview
    data object Invalid : InvitationPreview
}

/**
 * Strict import of scanned or pasted text. Only surrounding whitespace is trimmed, as the invitation contract allows;
 * the payload itself is never altered.
 */
fun previewInvitation(text: String): InvitationPreview {
    val invitation = try {
        PairingInvitation.importText(text.trim())
    } catch (_: IllegalArgumentException) {
        return InvitationPreview.Invalid
    } catch (_: IllegalStateException) {
        return InvitationPreview.Invalid
    }
    return InvitationPreview.Parsed(
        macID = hex(invitation.macID.copyBytes()),
        accountID = hex(invitation.accountID.copyBytes()),
        label = invitation.label,
        fingerprint = invitation.fingerprint(),
    )
}

/**
 * The preview to show while the user types or pastes into the field: a complete invitation is read at once, and
 * anything else returns null and waits for Read invitation, so a half-typed text never shows as invalid.
 */
fun previewWhileTyping(text: String): InvitationPreview.Parsed? = previewInvitation(text) as? InvitationPreview.Parsed

internal fun hex(bytes: ByteArray): String = bytes.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
