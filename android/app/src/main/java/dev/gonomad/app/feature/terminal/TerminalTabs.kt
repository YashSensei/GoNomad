package dev.gonomad.app.feature.terminal

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.gonomad.app.ffi.TerminalRunState
import dev.gonomad.app.ffi.TerminalTab
import dev.gonomad.app.ui.components.HSpace
import dev.gonomad.app.ui.components.HairlineDivider
import dev.gonomad.app.ui.components.MonoText
import dev.gonomad.app.ui.components.StateDot
import dev.gonomad.app.ui.components.VSpace
import dev.gonomad.app.ui.theme.GoNomadTheme
import dev.gonomad.app.ui.theme.Mono
import dev.gonomad.app.ui.theme.Space
import dev.gonomad.app.ui.theme.semantic

/**
 * The tab pill row (§13.5).
 *
 * Horizontally scrollable, one pill per open terminal, plus one button that
 * spawns another. There is deliberately **no close affordance on a pill**: a row
 * of small targets next to a running build is the wrong place to put a kill
 * switch, so closing lives in the switcher only.
 */
@Composable
fun TerminalTabRow(
    tabs: List<TerminalTab>,
    activeId: ULong?,
    onSelect: (ULong) -> Unit,
    onNew: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyRow(
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainerLow)
            .padding(vertical = Space.s),
        contentPadding = PaddingValues(horizontal = Space.s),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        items(tabs, key = { it.ptyId.toString() }) { tab ->
            TabPill(
                tab = tab,
                active = tab.ptyId == activeId,
                onClick = { onSelect(tab.ptyId) },
            )
        }
        item(key = "new-terminal") {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(999.dp))
                    .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                    .clickable(onClick = onNew),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Add,
                    contentDescription = "New terminal here",
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
    }
}

@Composable
private fun TabPill(tab: TerminalTab, active: Boolean, onClick: () -> Unit) {
    val semantic = MaterialTheme.semantic
    val container = if (active) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceContainerHigh
    }
    val label = when {
        active -> MaterialTheme.colorScheme.primary
        tab.running -> MaterialTheme.colorScheme.onSurface
        else -> semantic.textLow
    }

    var pill = Modifier
        .defaultMinSize(minHeight = 40.dp)
        .clip(RoundedCornerShape(999.dp))
        .background(container)
    if (active) {
        pill = pill.border(1.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(999.dp))
    }

    Row(
        modifier = pill
            .clickable(onClick = onClick)
            .padding(horizontal = Space.m)
            .clearAndSetSemantics {
                selected = active
                contentDescription = describe(tab)
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        StateDot(colour = if (tab.running) semantic.ok else semantic.textFaint, size = 7.dp)
        HSpace(Space.s)
        Text(
            text = tab.title,
            style = Mono.label,
            color = label,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        // The dot is never the only signal for a stopped shell.
        if (!tab.running) {
            HSpace(Space.xs)
            Text(text = "exited", style = Mono.label, color = semantic.textFaint)
        }
        if (tab.hasUnread) {
            HSpace(Space.s)
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary),
            )
        }
    }
}

/**
 * The full-screen switcher (§13.5).
 *
 * Each card carries the tail of that terminal's screen, because "which one was
 * the dev server?" is answered by what it last printed and by nothing else. This
 * is also the only place a terminal can be closed, and the button says so.
 */
@Composable
fun TerminalSwitcher(
    tabs: List<TerminalTab>,
    activeId: ULong?,
    onSelect: (ULong) -> Unit,
    onCloseTab: (ULong) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .statusBarsPadding()
                .padding(horizontal = Space.s, vertical = Space.xs),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "Terminals",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier
                    .weight(1f)
                    .padding(start = Space.s),
            )
            IconButton(onClick = onDismiss, modifier = Modifier.size(48.dp)) {
                Icon(
                    imageVector = Icons.Rounded.Close,
                    contentDescription = "Close the switcher",
                    tint = MaterialTheme.colorScheme.onBackground,
                )
            }
        }
        HairlineDivider()

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                start = Space.l,
                end = Space.l,
                top = Space.m,
                bottom = Space.xxl,
            ),
            verticalArrangement = Arrangement.spacedBy(Space.m),
        ) {
            items(tabs, key = { it.ptyId.toString() }) { tab ->
                SwitcherCard(
                    tab = tab,
                    active = tab.ptyId == activeId,
                    onSelect = { onSelect(tab.ptyId) },
                    onClose = { onCloseTab(tab.ptyId) },
                )
            }
        }
    }
}

@Composable
private fun SwitcherCard(
    tab: TerminalTab,
    active: Boolean,
    onSelect: () -> Unit,
    onClose: () -> Unit,
) {
    val semantic = MaterialTheme.semantic
    // The tail, not the head: a terminal's meaning is in what it printed last.
    val preview = remember(tab.screen) {
        tab.screen.split('\n').dropLastWhile { it.isBlank() }.takeLast(THUMBNAIL_LINES)
    }

    var card = Modifier
        .fillMaxWidth()
        .clip(RoundedCornerShape(16.dp))
        .background(MaterialTheme.colorScheme.surfaceContainer)
    if (active) {
        card = card.border(1.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(16.dp))
    }

    Column(modifier = card.padding(Space.l)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            StateDot(colour = if (tab.running) semantic.ok else semantic.textFaint, size = 8.dp)
            HSpace(Space.s)
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = tab.title,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                MonoText(text = "pty ${tab.ptyId}  ·  ${if (tab.running) "running" else "exited"}")
            }
            if (tab.hasUnread) {
                Text(
                    text = "new output",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }

        VSpace(Space.m)

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                .clickable(onClick = onSelect)
                .padding(Space.m)
                .clearAndSetSemantics { contentDescription = "Switch to ${describe(tab)}" },
        ) {
            Column {
                for (line in preview) {
                    Text(
                        text = line.ifEmpty { " " },
                        style = Mono.label,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }

        VSpace(Space.s)

        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onSelect, modifier = Modifier.heightIn(min = 48.dp)) {
                Text("Switch to this")
            }
            HSpace(Space.s)
            // Explicit, worded, and only here. Nothing about leaving a screen or
            // changing tabs ends a terminal.
            TextButton(onClick = onClose, modifier = Modifier.heightIn(min = 48.dp)) {
                Icon(
                    imageVector = Icons.Rounded.DeleteOutline,
                    contentDescription = null,
                    tint = semantic.danger,
                    modifier = Modifier.size(18.dp),
                )
                HSpace(Space.xs)
                Text("Close", color = semantic.danger)
            }
        }
    }
}

private const val THUMBNAIL_LINES = 6

private fun describe(tab: TerminalTab): String = buildString {
    append("terminal ")
    append(tab.title)
    append(", pty ")
    append(tab.ptyId)
    append(if (tab.running) ", running" else ", exited")
    if (tab.hasUnread) append(", new output")
}

// --- previews ---------------------------------------------------------------

private fun previewTab(
    id: ULong,
    cwd: String,
    screen: String,
    state: TerminalRunState = TerminalRunState.RUNNING,
    unread: Boolean = false,
) = TerminalTab(
    ptyId = id,
    cwd = cwd,
    screen = screen,
    cursorRow = 0u,
    cursorCol = 0u,
    runState = state,
    hasUnread = unread,
    cols = 80u,
    rows = 24u,
)

internal val previewTabs = listOf(
    previewTab(
        1uL,
        "C:/Users/dev/src/gonomad",
        "PS C:\\Users\\dev\\src\\gonomad> cargo test\nrunning 24 tests\ntest result: ok.",
    ),
    previewTab(
        2uL,
        "C:/Users/dev/src/atlas-api",
        "> atlas-api@1.0.0 dev\n> tsx watch src/index.ts\n\nlistening on :8080",
        unread = true,
    ),
    previewTab(
        3uL,
        "C:/Users/dev/src/gonomad/crates",
        "PS C:\\Users\\dev\\src\\gonomad\\crates> exit",
        state = TerminalRunState.EXITED,
    ),
)

@Preview(name = "Terminal tabs", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun TerminalTabRowPreview() {
    GoNomadTheme {
        TerminalTabRow(tabs = previewTabs, activeId = 1uL, onSelect = {}, onNew = {})
    }
}

@Preview(name = "Terminal switcher", showBackground = true, backgroundColor = 0xFF0E1116, heightDp = 1000)
@Composable
private fun TerminalSwitcherPreview() {
    GoNomadTheme {
        TerminalSwitcher(
            tabs = previewTabs,
            activeId = 1uL,
            onSelect = {},
            onCloseTab = {},
            onDismiss = {},
        )
    }
}
