package dev.remozio.phone.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** Native operations the shared screens need. The iOS shell implements them with AVFoundation and UIPasteboard. */
interface PhoneServices {
    /** Opens the camera scanner; [onResult] receives the QR text, or null when the user cancels or nothing is read. */
    fun scanQrCode(onResult: (String?) -> Unit)
    fun pasteText(): String?
}

private enum class Screen { Computers, AddComputer }

private val CardShape = RoundedCornerShape(14.dp)

@Composable
fun RemozioApp(services: PhoneServices) {
    var screen by remember { mutableStateOf(Screen.Computers) }
    RemozioTheme {
        Box(Modifier.fillMaxSize().background(LocalPalette.current.background).safeDrawingPadding()) {
            // A push to Add computer slides in from the right, and Back reverses it, as in an iOS navigation stack.
            AnimatedContent(screen, transitionSpec = { push(forward = targetState == Screen.AddComputer) }) { current ->
                when (current) {
                    Screen.Computers -> ComputersScreen(onAdd = { screen = Screen.AddComputer })
                    Screen.AddComputer -> AddComputerScreen(services, onBack = { screen = Screen.Computers })
                }
            }
        }
    }
}

private fun push(forward: Boolean): ContentTransform {
    val sign = if (forward) 1 else -1
    return (slideInHorizontally(tween(300)) { sign * it } + fadeIn(tween(300))) togetherWith
        (slideOutHorizontally(tween(300)) { -sign * it / 3 } + fadeOut(tween(200)))
}

@Composable
private fun ComputersScreen(onAdd: () -> Unit) {
    val palette = LocalPalette.current
    // The screen scrolls, so at the largest text sizes Add computer stays reachable; when there is room, the
    // empty state sits in the middle of the screen.
    BoxWithConstraints(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxWidth().heightIn(min = maxHeight).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
        Column {
            Spacer(Modifier.height(44.dp))
            BasicText("Computers", style = Type.largeTitle.copy(color = palette.text))
        }
        Column(
            Modifier.fillMaxWidth().padding(vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Badge(Icons.laptop, size = 96.dp, iconSize = 44.dp)
            Spacer(Modifier.height(20.dp))
            BasicText("No computers yet.", style = Type.headline.copy(color = palette.text))
            Spacer(Modifier.height(8.dp))
            BasicText(
                "Add a computer with the QR code that it shows.",
                style = Type.body.copy(color = palette.secondary, textAlign = TextAlign.Center),
            )
            Spacer(Modifier.height(28.dp))
            PrimaryButton("Add computer", "add-computer", onClick = onAdd)
        }
        Spacer(Modifier.height(56.dp))
        }
    }
}

@Composable
private fun AddComputerScreen(services: PhoneServices, onBack: () -> Unit) {
    val palette = LocalPalette.current
    var text by remember { mutableStateOf("") }
    var preview by remember { mutableStateOf<InvitationPreview?>(null) }
    // The last result stays composed while it fades out after the text changes.
    var shown by remember { mutableStateOf<InvitationPreview?>(null) }
    if (preview != null) shown = preview
    val focus = LocalFocusManager.current
    val scroll = rememberScrollState()
    fun show(input: String?) {
        if (input == null) return
        // Closing the keyboard keeps the result from being hidden under it.
        text = input
        preview = previewInvitation(input)
        focus.clearFocus()
    }
    LaunchedEffect(preview) {
        if (preview == null) return@LaunchedEffect
        withFrameNanos { }
        scroll.animateScrollTo(scroll.maxValue)
    }
    // A tap outside the text field closes the keyboard. The root safeDrawingPadding includes the keyboard inset,
    // so the content scrolls above the keyboard while it is open.
    Column(Modifier.fillMaxSize().pointerInput(Unit) { detectTapGestures { focus.clearFocus() } }) {
        // Back stays outside the scrolling column, so scrolling to a result never hides it.
        Row(
            Modifier.padding(start = 8.dp, top = 4.dp).clip(RoundedCornerShape(8.dp)).testTag("back")
                .clickable(role = Role.Button, onClick = onBack).padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Glyph(Icons.chevronLeft, palette.link, 22.dp)
            BasicText("Computers", style = Type.body.copy(color = palette.link))
        }
        Column(
            Modifier.verticalScroll(scroll).padding(horizontal = 20.dp).padding(bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            BasicText("Add computer", style = Type.largeTitle.copy(color = palette.text))
            BasicText(
                "Scan the QR code that the computer shows, or paste its invitation text.",
                style = Type.body.copy(color = palette.secondary),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Tile(Icons.qrCode, "Scan QR code", "scan", Modifier.weight(1f)) { services.scanQrCode(::show) }
                Tile(Icons.clipboard, "Paste", "paste", Modifier.weight(1f)) { show(services.pasteText()) }
            }
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                BasicText("Invitation text", Modifier.padding(start = 4.dp), style = Type.caption.copy(color = palette.secondary))
                Box(Modifier.fillMaxWidth().clip(CardShape).background(palette.surface).padding(14.dp)) {
                    if (text.isEmpty()) BasicText("remozio-pairing:v1:…", style = Type.code.copy(color = palette.secondary))
                    BasicTextField(
                        value = text,
                        onValueChange = { input ->
                            val parsed = previewWhileTyping(input)
                            if (parsed != null) {
                                text = input
                                preview = parsed
                                focus.clearFocus()
                            } else {
                                text = input
                                preview = null
                            }
                        },
                        textStyle = Type.code.copy(color = palette.text),
                        cursorBrush = SolidColor(palette.link),
                        modifier = Modifier.fillMaxWidth().heightIn(min = 72.dp).testTag("invitation-text"),
                    )
                }
            }
            PrimaryButton("Read invitation", "read", enabled = text.isNotBlank()) { show(text) }
            // Fade only: an expanding result would still grow while the screen scrolls to its end.
            AnimatedVisibility(preview != null, enter = fadeIn(tween(250)), exit = fadeOut(tween(150))) {
                when (val current = shown) {
                    null -> Unit
                    InvitationPreview.Invalid -> InvalidInvitation()
                    is InvitationPreview.Parsed -> ParsedInvitation(current)
                }
            }
        }
    }
}

@Composable
private fun ParsedInvitation(preview: InvitationPreview.Parsed) {
    val palette = LocalPalette.current
    Column(Modifier.testTag("parsed"), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Badge(Icons.laptop, size = 44.dp, iconSize = 24.dp)
                Spacer(Modifier.size(12.dp))
                BasicText(preview.label, Modifier.weight(1f).testTag("label"), style = Type.headline.copy(color = palette.text))
                Spacer(Modifier.size(8.dp))
                BasicText(
                    "Unverified",
                    Modifier.clip(CircleShape).background(palette.warningSoft).padding(horizontal = 10.dp, vertical = 4.dp),
                    style = Type.chip.copy(color = palette.warning),
                )
            }
            Separator()
            // The fingerprint is the value the user compares with the computer, so it comes right after the name,
            // in a grid of eight-character groups that can be compared one at a time, with that comparison as its helper line.
            BasicText("Fingerprint", style = Type.caption.copy(color = palette.secondary))
            Fingerprint(preview.fingerprint)
            BasicText("Must match the fingerprint that the computer shows.", style = Type.caption.copy(color = palette.secondary))
            Separator()
            Detail("Mac ID", preview.macID, "mac-id")
            Detail("Account ID", preview.accountID, "account-id")
        }
        Note(Icons.info, palette.warning, palette.warningSoft,
            "These are unverified invitation claims. This build does not connect to the computer or save it.")
    }
}

@Composable
private fun InvalidInvitation() {
    val palette = LocalPalette.current
    Column(Modifier.testTag("invalid")) {
        Note(Icons.error, palette.error, palette.errorSoft, "This is not a valid Remozio invitation.",
            "Check that you copied the whole text, starting with remozio-pairing:v1:")
    }
}

@Composable
private fun Fingerprint(fingerprint: String) {
    val palette = LocalPalette.current
    val groups = fingerprint.split('-')
    Column(Modifier.fillMaxWidth().testTag("fingerprint"), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        // Two groups per row: four groups of eight do not fit the width of a phone at this size.
        for (row in groups.chunked(2)) {
            Row(Modifier.fillMaxWidth()) {
                for (group in row) BasicText(group, Modifier.weight(1f), style = Type.fingerprint.copy(color = palette.text))
            }
        }
    }
}

@Composable
private fun Detail(name: String, value: String, tag: String) {
    val palette = LocalPalette.current
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        BasicText(name, style = Type.caption.copy(color = palette.secondary))
        BasicText(value, Modifier.testTag(tag), style = Type.code.copy(color = palette.text))
    }
}

@Composable
private fun Card(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxWidth().clip(CardShape).background(LocalPalette.current.surface).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        content = content,
    )
}

@Composable
private fun Separator() {
    Box(Modifier.fillMaxWidth().padding(vertical = 2.dp).height(0.5.dp).background(LocalPalette.current.separator))
}

@Composable
private fun Note(icon: ImageVector, tint: Color, background: Color, title: String, helper: String? = null) {
    val palette = LocalPalette.current
    Row(Modifier.fillMaxWidth().clip(CardShape).background(background).padding(14.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Glyph(icon, tint, 20.dp)
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            BasicText(title, style = Type.body.copy(color = palette.text))
            if (helper != null) BasicText(helper, style = Type.caption.copy(color = palette.secondary))
        }
    }
}

@Composable
private fun Badge(icon: ImageVector, size: Dp, iconSize: Dp) {
    val palette = LocalPalette.current
    Box(Modifier.size(size).clip(CircleShape).background(palette.accentSoft), contentAlignment = Alignment.Center) {
        Glyph(icon, palette.link, iconSize)
    }
}

@Composable
private fun Tile(icon: ImageVector, label: String, tag: String, modifier: Modifier, onClick: () -> Unit) {
    val palette = LocalPalette.current
    Column(
        modifier.clip(CardShape).testTag(tag).background(palette.surface)
            .clickable(role = Role.Button, onClick = onClick).padding(vertical = 18.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Glyph(icon, palette.link, 28.dp)
        BasicText(label, style = Type.button.copy(color = palette.link))
    }
}

@Composable
private fun PrimaryButton(label: String, tag: String, enabled: Boolean = true, onClick: () -> Unit) {
    val palette = LocalPalette.current
    Box(
        // A minimum height, not a fixed one, so the label can grow with large text sizes.
        Modifier.fillMaxWidth().heightIn(min = 50.dp).clip(CardShape).testTag(tag).alpha(if (enabled) 1f else 0.4f)
            .background(palette.accent).clickable(enabled = enabled, role = Role.Button, onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        BasicText(
            label,
            Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            style = Type.button.copy(color = palette.onAccent, textAlign = TextAlign.Center),
        )
    }
}

@Composable
private fun Glyph(icon: ImageVector, tint: Color, size: Dp) {
    Image(icon, contentDescription = null, Modifier.size(size), colorFilter = ColorFilter.tint(tint))
}
