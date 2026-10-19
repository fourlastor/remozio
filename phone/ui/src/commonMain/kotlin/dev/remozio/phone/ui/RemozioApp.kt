package dev.remozio.phone.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.withFrameNanos
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Native operations the shared screens need. The iOS shell implements them with AVFoundation and UIPasteboard. */
interface PhoneServices {
    /** Opens the camera scanner; [onResult] receives the QR text, or null when the user cancels or nothing is read. */
    fun scanQrCode(onResult: (String?) -> Unit)
    fun pasteText(): String?
}

private enum class Screen { Computers, AddComputer }

/** Every color the screens use. iOS picks the status bar icon color from the system appearance, so the
 * background must follow it too. */
private class Palette(val background: Color, val text: Color, val secondary: Color, val border: Color, val accent: Color)

private val LightPalette = Palette(Color.White, Color(0xFF111111), Color(0xFF6B6B6B), Color(0xFF8E8E8E), Color(0xFF1F5FD6))
private val DarkPalette = Palette(Color(0xFF111111), Color(0xFFF2F2F2), Color(0xFFA0A0A0), Color(0xFF6E6E6E), Color(0xFF2F6BE0))
private val LocalPalette = staticCompositionLocalOf { LightPalette }

@Composable
fun RemozioApp(services: PhoneServices) {
    var screen by remember { mutableStateOf(Screen.Computers) }
    val palette = if (isSystemInDarkTheme()) DarkPalette else LightPalette
    CompositionLocalProvider(LocalPalette provides palette) {
        Column(Modifier.fillMaxSize().background(palette.background).safeDrawingPadding().padding(16.dp)) {
            when (screen) {
                Screen.Computers -> ComputersScreen(onAdd = { screen = Screen.AddComputer })
                Screen.AddComputer -> AddComputerScreen(services, onBack = { screen = Screen.Computers })
            }
        }
    }
}

@Composable
private fun ComputersScreen(onAdd: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Title("Computers")
        Body("No computers yet.")
        Action("Add computer", "add-computer", onAdd)
    }
}

@Composable
private fun AddComputerScreen(services: PhoneServices, onBack: () -> Unit) {
    var text by remember { mutableStateOf("") }
    var preview by remember { mutableStateOf<InvitationPreview?>(null) }
    val focus = LocalFocusManager.current
    val scroll = rememberScrollState()
    fun show(input: String?) {
        if (input == null) return
        // Closing the keyboard keeps the result from being hidden under it.
        focus.clearFocus()
        text = input
        preview = previewInvitation(input)
    }
    LaunchedEffect(preview) {
        if (preview == null) return@LaunchedEffect
        withFrameNanos { }
        scroll.animateScrollTo(scroll.maxValue)
    }
    // Back and the title stay outside the scrolling column, so scrolling to a result never hides or cuts them.
    Column(Modifier.padding(bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Action("Back", "back", onBack)
        }
        Title("Add computer")
    }
    Column(Modifier.verticalScroll(scroll), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Body("Scan the QR code that the computer shows, or paste its invitation text.")
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Action("Scan QR code", "scan") { services.scanQrCode(::show) }
            Action("Paste", "paste") { show(services.pasteText()) }
        }
        val palette = LocalPalette.current
        BasicTextField(
            value = text,
            onValueChange = { text = it; preview = null },
            textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp, color = palette.text),
            cursorBrush = SolidColor(palette.accent),
            modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp).testTag("invitation-text")
                .border(1.dp, palette.border, RoundedCornerShape(8.dp)).padding(8.dp),
        )
        Action("Read invitation", "read") { show(text) }
        when (val current = preview) {
            null -> Unit
            InvitationPreview.Invalid -> Body("This is not a valid Remozio invitation.", Modifier.testTag("invalid"))
            is InvitationPreview.Parsed -> ParsedInvitation(current)
        }
    }
}

@Composable
private fun ParsedInvitation(preview: InvitationPreview.Parsed) {
    // The fingerprint is the value the user compares with the computer, so it comes right after the name,
    // with that comparison as its helper line.
    Column(Modifier.testTag("parsed"), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Field("Label", preview.label, "label")
        Field("Fingerprint", preview.fingerprint, "fingerprint", "Must match the fingerprint that the computer shows.")
        Field("Mac ID", preview.macID, "mac-id")
        Field("Account ID", preview.accountID, "account-id")
        Body("These are unverified invitation claims. This build does not connect to the computer or save it.")
    }
}

@Composable
private fun Title(text: String) =
    BasicText(text, style = TextStyle(fontSize = 28.sp, fontWeight = FontWeight.Bold, color = LocalPalette.current.text))

@Composable
private fun Body(text: String, modifier: Modifier = Modifier) =
    BasicText(text, modifier, style = TextStyle(fontSize = 16.sp, color = LocalPalette.current.text))

@Composable
private fun Field(name: String, value: String, tag: String, helper: String? = null) {
    val palette = LocalPalette.current
    Column {
        BasicText(name, style = TextStyle(fontSize = 13.sp, color = palette.secondary))
        BasicText(value, Modifier.testTag(tag), style = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 15.sp, color = palette.text))
        if (helper != null) BasicText(helper, style = TextStyle(fontSize = 13.sp, color = palette.secondary))
    }
}

@Composable
private fun Action(label: String, tag: String, onClick: () -> Unit) {
    BasicText(
        label,
        Modifier.testTag(tag).clickable(role = Role.Button, onClick = onClick)
            .background(LocalPalette.current.accent, RoundedCornerShape(8.dp)).padding(horizontal = 16.dp, vertical = 10.dp),
        style = TextStyle(color = Color.White, fontSize = 16.sp),
    )
}
