package dev.gonomad.app.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.shape.RoundedCornerShape

/**
 * Colours that Material 3 has no slot for but that the product needs everywhere:
 * connection tier, git state, agent state, and the code-token set.
 *
 * Kept in a CompositionLocal rather than as top-level constants so a light
 * scheme can be introduced later without touching a single call site.
 */
@Immutable
data class SemanticColors(
    val ok: Color,
    val okContainer: Color,
    val warn: Color,
    val warnContainer: Color,
    val danger: Color,
    val dangerContainer: Color,
    val accentDim: Color,
    val textLow: Color,
    val textFaint: Color,
    val well: Color,
    val hairline: Color,
    val edge: Color,
    val synKeyword: Color,
    val synString: Color,
    val synComment: Color,
    val synNumber: Color,
    val synType: Color,
)

private val DarkSemantics = SemanticColors(
    ok = StateOk,
    okContainer = StateOkContainer,
    warn = StateWarn,
    warnContainer = StateWarnContainer,
    danger = StateDanger,
    dangerContainer = StateDangerContainer,
    accentDim = AccentDim,
    textLow = TextLow,
    textFaint = TextFaint,
    well = InkWell,
    hairline = Hairline,
    edge = Edge,
    synKeyword = SynKeyword,
    synString = SynString,
    synComment = SynComment,
    synNumber = SynNumber,
    synType = SynType,
)

private val LocalSemanticColors = staticCompositionLocalOf { DarkSemantics }

/**
 * The dark scheme. Note that `surface` equals `background`: the difference
 * between levels is carried entirely by the `surfaceContainer*` ramp, which is
 * what makes cards blend instead of outline.
 */
private val GoNomadDarkScheme: ColorScheme = darkColorScheme(
    primary = Accent,
    onPrimary = OnAccent,
    primaryContainer = AccentContainer,
    onPrimaryContainer = Accent,

    secondary = TextMid,
    onSecondary = Ink,
    secondaryContainer = Slate2,
    onSecondaryContainer = TextHigh,

    tertiary = AccentDim,
    onTertiary = TextHigh,
    tertiaryContainer = Slate2,
    onTertiaryContainer = TextHigh,

    background = Ink,
    onBackground = TextHigh,

    surface = Ink,
    onSurface = TextHigh,
    surfaceVariant = Slate2,
    onSurfaceVariant = TextMid,

    surfaceContainerLowest = InkWell,
    surfaceContainerLow = Slate1,
    surfaceContainer = Slate1,
    surfaceContainerHigh = Slate2,
    surfaceContainerHighest = Slate3,

    surfaceTint = Accent,
    inverseSurface = TextHigh,
    inverseOnSurface = Ink,

    outline = Edge,
    outlineVariant = Hairline,

    error = StateDanger,
    onError = Ink,
    errorContainer = StateDangerContainer,
    onErrorContainer = StateDanger,

    scrim = Color(0xCC05070A),
)

/** Corners are round enough to read as soft, tight enough to read as a tool. */
private val GoNomadShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(18.dp),
    extraLarge = RoundedCornerShape(24.dp),
)

/** Spacing scale. Generous by Material standards; the app is mostly text. */
object Space {
    val xs = 4.dp
    val s = 8.dp
    val m = 12.dp
    val l = 16.dp
    val xl = 24.dp
    val xxl = 32.dp
}

/**
 * Only [Dark] exists today. Adding `Light` means adding one branch in each
 * `when` below plus a `LightSemantics` value — no call site changes.
 */
enum class ThemeMode { Dark }

@Composable
fun GoNomadTheme(
    mode: ThemeMode = ThemeMode.Dark,
    content: @Composable () -> Unit,
) {
    // Dynamic colour is deliberately not wired up. The point of this palette is
    // a consistent identity across devices, and a wallpaper-derived lilac would
    // undo it (ARCHITECTURE.md 6.1 calls for a custom developer-tool theme).
    val scheme = when (mode) {
        ThemeMode.Dark -> GoNomadDarkScheme
    }
    val semantics = when (mode) {
        ThemeMode.Dark -> DarkSemantics
    }

    CompositionLocalProvider(LocalSemanticColors provides semantics) {
        MaterialTheme(
            colorScheme = scheme,
            typography = GoNomadTypography,
            shapes = GoNomadShapes,
            content = content,
        )
    }
}

/** `MaterialTheme.semantic` — the project's extension slot. */
val MaterialTheme.semantic: SemanticColors
    @Composable
    @ReadOnlyComposable
    get() = LocalSemanticColors.current
