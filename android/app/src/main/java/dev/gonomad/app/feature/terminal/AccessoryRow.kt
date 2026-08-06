package dev.gonomad.app.feature.terminal

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.gonomad.app.ui.theme.GoNomadTheme
import dev.gonomad.app.ui.theme.Mono
import dev.gonomad.app.ui.theme.Space

/**
 * One key on the accessory bar.
 *
 * @param label what is printed on the cap
 * @param send the raw bytes this key writes to the PTY, or null for a modifier
 * @param spoken how TalkBack should name it ("left arrow", not "<")
 */
data class AccessoryKey(
    val id: String,
    val label: String,
    val send: String?,
    val spoken: String,
)

/** Which sticky modifier, if any, is armed for the next keypress. */
enum class StickyModifier { None, Ctrl, Alt }

/**
 * The accessory key row from ARCHITECTURE.md 23.2.
 *
 * `Ctrl` and `Alt` are **sticky**: tapping arms the modifier, and the next key
 * is sent modified, after which the modifier disarms. This is the only design
 * that works one-handed — a phone cannot hold a modifier down while pressing a
 * second key, and two-thumb chording on a 6-inch screen is worse than useless.
 *
 * An armed modifier is shown with a filled cap, a ring, *and* a TalkBack state
 * description, so the state is never carried by colour alone.
 */
@Composable
fun AccessoryRow(
    sticky: StickyModifier,
    onKey: (AccessoryKey) -> Unit,
    onToggleModifier: (StickyModifier) -> Unit,
    modifier: Modifier = Modifier,
) {
    val haptics = LocalHapticFeedback.current

    LazyRow(
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .padding(vertical = Space.s),
        contentPadding = PaddingValues(horizontal = Space.s),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        items(AccessoryKeys.row, key = { it.id }) { key ->
            val which = AccessoryKeys.modifierFor(key)
            if (which != null) {
                val armed = sticky == which
                KeyCap(
                    label = key.label,
                    spoken = key.spoken,
                    armed = armed,
                    stateText = if (armed) "armed for the next key" else "off",
                    onClick = {
                        haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                        onToggleModifier(which)
                    },
                )
            } else {
                KeyCap(
                    label = key.label,
                    spoken = key.spoken,
                    armed = false,
                    stateText = null,
                    onClick = {
                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onKey(key)
                    },
                )
            }
        }
    }
}

@Composable
private fun KeyCap(
    label: String,
    spoken: String,
    armed: Boolean,
    stateText: String?,
    onClick: () -> Unit,
) {
    val container = if (armed) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceContainerHighest
    }
    val content = if (armed) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.onSurface
    }

    var cap = Modifier
        // 48 dp is the accessibility floor, and this row is tapped more than
        // anything else in the app.
        .defaultMinSize(minWidth = 48.dp, minHeight = 48.dp)
        .clip(RoundedCornerShape(10.dp))
        .background(container)

    if (armed) {
        cap = cap.border(1.5.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(10.dp))
    }

    Box(
        modifier = cap
            .clickable(onClick = onClick)
            .padding(horizontal = Space.m)
            .clearAndSetSemantics {
                contentDescription = spoken
                if (stateText != null) stateDescription = stateText
            },
        contentAlignment = Alignment.Center,
    ) {
        Text(text = label, style = Mono.key, color = content)
    }
}

/**
 * The exact row specified in ARCHITECTURE.md 23.2:
 * `Esc Tab Ctrl Alt (left) (down) (up) (right) | / ~ $ -`
 *
 * Control bytes are built from code points rather than written as escapes, so
 * no invisible character can ever end up in this file.
 */
object AccessoryKeys {

    private val ESC = Char(0x1B).toString()
    private val TAB = Char(0x09).toString()
    private const val CSI_SUFFIX_UP = "[A"
    private const val CSI_SUFFIX_DOWN = "[B"
    private const val CSI_SUFFIX_RIGHT = "[C"
    private const val CSI_SUFFIX_LEFT = "[D"

    val row: List<AccessoryKey> = listOf(
        AccessoryKey("esc", "Esc", ESC, "Escape"),
        AccessoryKey("tab", "Tab", TAB, "Tab"),
        AccessoryKey("ctrl", "Ctrl", null, "Control, sticky modifier"),
        AccessoryKey("alt", "Alt", null, "Alt, sticky modifier"),
        AccessoryKey("left", "←", ESC + CSI_SUFFIX_LEFT, "Left arrow"),
        AccessoryKey("down", "↓", ESC + CSI_SUFFIX_DOWN, "Down arrow"),
        AccessoryKey("up", "↑", ESC + CSI_SUFFIX_UP, "Up arrow"),
        AccessoryKey("right", "→", ESC + CSI_SUFFIX_RIGHT, "Right arrow"),
        AccessoryKey("pipe", "|", "|", "Pipe"),
        AccessoryKey("slash", "/", "/", "Forward slash"),
        AccessoryKey("tilde", "~", "~", "Tilde"),
        AccessoryKey("dollar", "$", "$", "Dollar sign"),
        AccessoryKey("dash", "-", "-", "Hyphen"),
    )

    fun modifierFor(key: AccessoryKey): StickyModifier? = when (key.id) {
        "ctrl" -> StickyModifier.Ctrl
        "alt" -> StickyModifier.Alt
        else -> null
    }

    /**
     * Applies an armed modifier to a keystroke.
     *
     * Ctrl folds a letter to its control code (`Ctrl+C` becomes 0x03), which is
     * what a PTY actually expects. Alt prefixes with ESC, which is how every
     * terminal has encoded Meta since the VT220.
     */
    fun applyModifier(sticky: StickyModifier, raw: String): String = when (sticky) {
        StickyModifier.None -> raw

        StickyModifier.Ctrl -> {
            val c = raw.firstOrNull()?.uppercaseChar()
            if (c != null && c in 'A'..'Z') Char(c.code - 'A'.code + 1).toString() else raw
        }

        StickyModifier.Alt -> ESC + raw
    }
}

@Preview(name = "Accessory row · Ctrl armed", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun AccessoryRowPreview() {
    GoNomadTheme {
        AccessoryRow(sticky = StickyModifier.Ctrl, onKey = {}, onToggleModifier = {})
    }
}
