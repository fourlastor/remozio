package dev.remozio.phone.ui

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class InvitationPreviewTest {
    // The "ascii" row of protocol/vectors/pairing-invitation-v1.json.
    private val text = "remozio-pairing:v1:pwABAVABAQEBAQEBAQEBAQEBAQEBAlACAgICAgICAgICAgICAgICA2ZTdHVkaW8EWEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li_hp_m47n60p8D54WK84zV2sxXs7LtkBoN79R9QVYQQR88nsYjQNPfopSOAMEtRrDwIlp4nfyGzWmC0j8R2aZeAd3VRDbjtBAKT2axp90MNu6fa3mPOmCKZ4Et50ieHPRBgE"

    @Test fun validTextShowsTheIdentityAndFullFingerprint() {
        val preview = previewInvitation(text) as InvitationPreview.Parsed
        assertEquals("01".repeat(16), preview.macID)
        assertEquals("02".repeat(16), preview.accountID)
        assertEquals("Studio", preview.label)
        assertEquals("15448DD8-80A3E42E-81C4BE45-FA94CE71-0E577125-96136E08-5F07F24D-E63288DF", preview.fingerprint)
    }

    @Test fun surroundingWhitespaceFromAPasteIsAccepted() {
        assertTrue(previewInvitation("  $text\n") is InvitationPreview.Parsed)
    }

    @Test fun structurallyInvalidTextIsRejected() {
        val invalid = listOf("", "remozio-pairing:v1:", text.replace("remozio-pairing:v1:", "remozio-pairing:v2:"),
            "$text=", "$text" + "AA", text.substring(0, text.length - 4), text.replaceRange(30, 31, " "),
            "https://example.com/?$text", text.lowercase())
        for (candidate in invalid) assertEquals(InvitationPreview.Invalid, previewInvitation(candidate), candidate)
    }

    @Test fun wellFormedTextWithInvalidCborIsRejected() {
        // 0xff (bare break), 00 00 00 (trailing bytes), 0x01 (not a map), 0xa0 (empty map).
        for (payload in listOf("_w", "AAAA", "AQ", "oA")) {
            assertEquals(InvitationPreview.Invalid, previewInvitation("remozio-pairing:v1:$payload"), payload)
        }
    }

    @Test fun aChangedButValidInvitationShowsADifferentFingerprint() {
        // Changing the first Mac ID byte from 0x01 to 0x03 keeps the structure valid: the invitation has no checksum.
        val changed = text.replaceFirst("AVABAQEB", "AVADAQEB")
        val original = previewInvitation(text) as InvitationPreview.Parsed
        val altered = previewInvitation(changed) as InvitationPreview.Parsed
        assertNotEquals(original.macID, altered.macID)
        assertNotEquals(original.fingerprint, altered.fingerprint)
    }
}
