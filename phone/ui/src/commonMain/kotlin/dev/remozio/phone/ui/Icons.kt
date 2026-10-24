package dev.remozio.phone.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathBuilder
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

/** Line icons on a 24-unit grid, drawn in black and tinted where they are used. Foundation has no icon set. */
internal object Icons {
    val laptop = icon("laptop") {
        moveTo(5f, 5f); lineTo(19f, 5f); lineTo(19f, 15f); lineTo(5f, 15f); close()
        moveTo(2f, 19f); lineTo(22f, 19f)
    }
    val qrCode = icon("qr-code") {
        square(3f, 3f, 7f); square(14f, 3f, 7f); square(3f, 14f, 7f)
        moveTo(14f, 14f); lineTo(14f, 14.01f)
        moveTo(17.5f, 14f); lineTo(21f, 14f)
        moveTo(14f, 17.5f); lineTo(14f, 21f)
        moveTo(17.5f, 17.5f); lineTo(21f, 21f)
    }
    val clipboard = icon("clipboard") {
        moveTo(9f, 4f); lineTo(6f, 4f); lineTo(6f, 21f); lineTo(18f, 21f); lineTo(18f, 4f); lineTo(15f, 4f)
        square(9f, 2.5f, 6f, 3f)
    }
    val chevronLeft = icon("chevron-left") {
        moveTo(15f, 5f); lineTo(8f, 12f); lineTo(15f, 19f)
    }
    val error = icon("error") {
        circle()
        moveTo(9f, 9f); lineTo(15f, 15f)
        moveTo(15f, 9f); lineTo(9f, 15f)
    }
    val info = icon("info") {
        circle()
        moveTo(12f, 11f); lineTo(12f, 16.5f)
        moveTo(12f, 7.5f); lineTo(12f, 7.51f)
    }

    private fun PathBuilder.square(x: Float, y: Float, width: Float, height: Float = width) {
        moveTo(x, y); lineTo(x + width, y); lineTo(x + width, y + height); lineTo(x, y + height); close()
    }

    private fun PathBuilder.circle() {
        moveTo(21f, 12f)
        arcTo(9f, 9f, 0f, isMoreThanHalf = true, isPositiveArc = true, x1 = 3f, y1 = 12f)
        arcTo(9f, 9f, 0f, isMoreThanHalf = true, isPositiveArc = true, x1 = 21f, y1 = 12f)
    }

    private fun icon(name: String, draw: PathBuilder.() -> Unit): ImageVector =
        ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).path(
            stroke = SolidColor(Color.Black),
            strokeLineWidth = 2f,
            strokeLineCap = StrokeCap.Round,
            strokeLineJoin = StrokeJoin.Round,
            pathBuilder = draw,
        ).build()
}
