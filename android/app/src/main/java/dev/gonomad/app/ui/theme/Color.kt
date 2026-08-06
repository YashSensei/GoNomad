package dev.gonomad.app.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * One tonal family, near-black through slate, plus a single desaturated accent.
 *
 * The whole palette is deliberately low-contrast between *surfaces* (so cards
 * blend into the background instead of being outlined) while keeping high
 * contrast between surface and *text*. Depth is expressed by tint, never by
 * shadow — drop shadows on a near-black background read as grey smudge.
 */

// --- Neutral ramp -----------------------------------------------------------

/** Window background. Everything else is lifted from here. */
val Ink = Color(0xFF0E1116)

/** Below-background wells: terminal output, code blocks, text fields. */
val InkWell = Color(0xFF0A0D12)

/** Standard card. +1 step. */
val Slate1 = Color(0xFF151A21)

/** Raised element inside a card: chips, key caps, list highlight. +2 steps. */
val Slate2 = Color(0xFF1C222B)

/** Highest surface: bottom sheets, pressed key caps, dialogs. +3 steps. */
val Slate3 = Color(0xFF232B36)

/** Only for a genuine separator, never a card outline. */
val Hairline = Color(0xFF262E39)

/** A visible-but-quiet border, e.g. an armed modifier key. */
val Edge = Color(0xFF39434F)

// --- Text -------------------------------------------------------------------

val TextHigh = Color(0xFFE3E9F0)
val TextMid = Color(0xFF9BA6B4)
val TextLow = Color(0xFF6C7885)
val TextFaint = Color(0xFF4A5461)

// --- Accent -----------------------------------------------------------------

/** The one accent. Used for primary actions and "you are here", nothing else. */
val Accent = Color(0xFF5EC8C0)
val AccentDim = Color(0xFF3A8781)
val AccentContainer = Color(0xFF13302E)
val OnAccent = Color(0xFF04231F)

// --- Semantic state ---------------------------------------------------------
// Muted on purpose: these appear next to each other in lists, and saturated
// traffic-light colours would dominate a screen that is mostly text.

/** Connected / clean / success. */
val StateOk = Color(0xFF7FB891)
val StateOkContainer = Color(0xFF15251B)

/** Relayed / degraded / modified. */
val StateWarn = Color(0xFFD9A85C)
val StateWarnContainer = Color(0xFF2B2317)

/** Offline / error / destructive. */
val StateDanger = Color(0xFFD98A82)
val StateDangerContainer = Color(0xFF2E1D1C)

// --- Syntax-ish tokens for the file viewer ----------------------------------
// Not a real highlighter; a small, palette-consistent token set.

val SynKeyword = Color(0xFF8FA6D8)
val SynString = Color(0xFF9EC08A)
val SynComment = Color(0xFF5C6672)
val SynNumber = Color(0xFFD2A67A)
val SynType = Color(0xFF6FC3BC)
