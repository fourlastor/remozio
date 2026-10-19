package dev.remozio.phone.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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

@Composable
fun RemozioApp(services: PhoneServices) {
    var screen by remember { mutableStateOf(Screen.Computers) }
    Column(Modifier.fillMaxSize().background(Color.White).safeDrawingPadding().padding(16.dp)) {
        when (screen) {
            Screen.Computers -> ComputersScreen(onAdd = { screen = Screen.AddComputer })
            Screen.AddComputer -> AddComputerScreen(services, onBack = { screen = Screen.Computers })
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
    fun show(input: String?) {
        if (input == null) return
        text = input
        preview = previewInvitation(input)
    }
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Action("Back", "back", onBack)
        }
        Title("Add computer")
        Body("Scan the QR code that the computer shows, or paste its invitation text.")
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Action("Scan QR code", "scan") { services.scanQrCode(::show) }
            Action("Paste", "paste") { show(services.pasteText()) }
        }
        BasicTextField(
            value = text,
            onValueChange = { text = it; preview = null },
            textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp),
            modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp).testTag("invitation-text")
                .border(1.dp, Color.Gray, RoundedCornerShape(8.dp)).padding(8.dp),
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
    Column(Modifier.testTag("parsed"), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Field("Label", preview.label, "label")
        Field("Mac ID", preview.macID, "mac-id")
        Field("Account ID", preview.accountID, "account-id")
        Field("Fingerprint", preview.fingerprint, "fingerprint")
        Body("These are unverified invitation claims. Compare the fingerprint with the one that the computer shows. " +
            "This build does not connect to the computer or save it.")
    }
}

@Composable
private fun Title(text: String) = BasicText(text, style = TextStyle(fontSize = 28.sp, fontWeight = FontWeight.Bold))

@Composable
private fun Body(text: String, modifier: Modifier = Modifier) = BasicText(text, modifier, style = TextStyle(fontSize = 16.sp))

@Composable
private fun Field(name: String, value: String, tag: String) {
    Column {
        BasicText(name, style = TextStyle(fontSize = 13.sp, color = Color.Gray))
        BasicText(value, Modifier.testTag(tag), style = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 15.sp))
    }
}

@Composable
private fun Action(label: String, tag: String, onClick: () -> Unit) {
    BasicText(
        label,
        Modifier.testTag(tag).clickable(role = Role.Button, onClick = onClick)
            .background(Color(0xFF1F5FD6), RoundedCornerShape(8.dp)).padding(horizontal = 16.dp, vertical = 10.dp),
        style = TextStyle(color = Color.White, fontSize = 16.sp),
    )
}
