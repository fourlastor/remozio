package dev.remozio.phone.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * Every color the screens use, in the grouped style of iOS settings screens. iOS picks the status bar icon
 * color from the system appearance, so the background follows it too. Text pairs meet 4.5:1 and borders 3:1.
 */
internal class Palette(
    val background: Color,
    val surface: Color,
    val text: Color,
    val secondary: Color,
    val separator: Color,
    val accent: Color,
    /** Accent for text and icons; the button fill is too dark for text on the dark background. */
    val link: Color,
    val onAccent: Color,
    val accentSoft: Color,
    val warning: Color,
    val warningSoft: Color,
    val error: Color,
    val errorSoft: Color,
)

private val LightPalette = Palette(
    background = Color(0xFFF2F2F7), surface = Color.White, text = Color(0xFF111111), secondary = Color(0xFF6B6B70),
    separator = Color(0xFF8E8E93), accent = Color(0xFF1F5FD6), link = Color(0xFF1F5FD6), onAccent = Color.White, accentSoft = Color(0xFFE3ECFB),
    warning = Color(0xFF8A5300), warningSoft = Color(0xFFFFF3DC), error = Color(0xFFC0261C), errorSoft = Color(0xFFFDE8E6),
)

private val DarkPalette = Palette(
    background = Color.Black, surface = Color(0xFF1C1C1E), text = Color(0xFFF2F2F2), secondary = Color(0xFFA1A1A6),
    separator = Color(0xFF6E6E73), accent = Color(0xFF2F6BE0), link = Color(0xFF6FA0FF), onAccent = Color.White, accentSoft = Color(0xFF1B2A45),
    warning = Color(0xFFFFC266), warningSoft = Color(0xFF3A2C14), error = Color(0xFFFF8A80), errorSoft = Color(0xFF3D1A17),
)

internal val LocalPalette = staticCompositionLocalOf { LightPalette }

internal object Type {
    val largeTitle = TextStyle(fontSize = 34.sp, fontWeight = FontWeight.Bold, lineHeight = 41.sp)
    val headline = TextStyle(fontSize = 20.sp, fontWeight = FontWeight.SemiBold, lineHeight = 25.sp)
    val body = TextStyle(fontSize = 17.sp, lineHeight = 22.sp)
    val button = TextStyle(fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
    val caption = TextStyle(fontSize = 13.sp, lineHeight = 18.sp)
    val chip = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    val code = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp, lineHeight = 18.sp)
    val fingerprint = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 20.sp, fontWeight = FontWeight.Medium, lineHeight = 28.sp)
}

@Composable
internal fun RemozioTheme(content: @Composable () -> Unit) {
    val palette = if (isSystemInDarkTheme()) DarkPalette else LightPalette
    CompositionLocalProvider(LocalPalette provides palette, content = content)
}
