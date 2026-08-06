package dev.gonomad.app.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.sp

/**
 * The UI family is the platform default (SF-alike on OEM skins, Roboto on
 * Pixel) — a bundled UI font buys nothing here. The *mono* family is the one
 * that matters, and it carries every path, hash, command, and line of code.
 *
 * Swap [MonoFamily] for JetBrains Mono by dropping the TTFs into `res/font`
 * and changing this one declaration; nothing else references a family.
 */
val MonoFamily: FontFamily = FontFamily.Monospace

private val UiFamily: FontFamily = FontFamily.Default

val GoNomadTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Light,
        fontSize = 34.sp,
        lineHeight = 40.sp,
        letterSpacing = (-0.5).sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 26.sp,
        lineHeight = 32.sp,
        letterSpacing = (-0.4).sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 21.sp,
        lineHeight = 28.sp,
        letterSpacing = (-0.2).sp,
    ),
    titleLarge = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 18.sp,
        lineHeight = 24.sp,
        letterSpacing = (-0.1).sp,
    ),
    titleMedium = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 15.sp,
        lineHeight = 20.sp,
    ),
    titleSmall = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
        lineHeight = 18.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 21.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 17.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 18.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.3.sp,
    ),
    labelSmall = TextStyle(
        fontFamily = UiFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 10.sp,
        lineHeight = 14.sp,
        letterSpacing = 0.6.sp,
    ),
)

/**
 * Monospace styles. These are not part of [Typography] because Material's slots
 * are all claimed by UI text, and code needs its own scale anyway.
 */
object Mono {
    /** Terminal output and file viewer bodies. */
    val body = TextStyle(
        fontFamily = MonoFamily,
        fontSize = 13.sp,
        lineHeight = 19.sp,
        letterSpacing = 0.sp,
    )

    /** Gutter line numbers; same metrics as [body] so rows align. */
    val gutter = TextStyle(
        fontFamily = MonoFamily,
        fontSize = 13.sp,
        lineHeight = 19.sp,
        textAlign = TextAlign.End,
    )

    /** Paths, hashes, short commands inline in UI text. */
    val label = TextStyle(
        fontFamily = MonoFamily,
        fontSize = 12.sp,
        lineHeight = 17.sp,
    )

    /** Accessory key caps. */
    val key = TextStyle(
        fontFamily = MonoFamily,
        fontSize = 14.sp,
        fontWeight = FontWeight.Medium,
        lineHeight = 18.sp,
    )

    /** The six-digit SAS. Wide tracking so digits are read one at a time. */
    val sas = TextStyle(
        fontFamily = MonoFamily,
        fontSize = 44.sp,
        fontWeight = FontWeight.Medium,
        lineHeight = 52.sp,
        letterSpacing = 8.sp,
    )
}
