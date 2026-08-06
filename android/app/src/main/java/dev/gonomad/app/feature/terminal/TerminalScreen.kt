package dev.gonomad.app.feature.terminal

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.ViewAgenda
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.gonomad.app.ffi.TerminalTab
import dev.gonomad.app.ui.common.ErrorAction
import dev.gonomad.app.ui.common.rememberTerminals
import dev.gonomad.app.ui.common.scopedViewModel
import dev.gonomad.app.ui.components.EmptyState
import dev.gonomad.app.ui.components.ErrorState
import dev.gonomad.app.ui.components.HSpace
import dev.gonomad.app.ui.components.HairlineDivider
import dev.gonomad.app.ui.components.MonoText
import dev.gonomad.app.ui.theme.GoNomadTheme
import dev.gonomad.app.ui.theme.Mono
import dev.gonomad.app.ui.theme.Space
import dev.gonomad.app.ui.theme.semantic

@Composable
fun TerminalScreen(cwd: String, onBack: () -> Unit) {
    val terminals = rememberTerminals()
    // One ViewModel for the whole screen, not one per path: the tabs are shared,
    // and a per-cwd instance would each hold its own idea of which is active.
    val vm: TerminalsViewModel = scopedViewModel(key = "terminals") { TerminalsViewModel(terminals) }
    val state by vm.state.collectAsStateWithLifecycle()

    // Arriving here asks for a terminal on this path. The repository decides
    // whether that means spawning one or selecting the one already open, so this
    // is safe to re-run on every entry.
    LaunchedEffect(cwd) { vm.onScreenEntered(cwd) }

    TerminalContent(
        state = state,
        onBack = onBack,
        onDraftChanged = vm::onDraftChanged,
        onSend = vm::send,
        onKey = vm::onAccessoryKey,
        onToggleModifier = vm::onToggleModifier,
        onRetry = vm::retry,
        onSelectTab = vm::selectTab,
        onNewTab = vm::newTerminal,
        onCloseTab = vm::closeTab,
        onOpenSwitcher = vm::openSwitcher,
        onCloseSwitcher = vm::closeSwitcher,
        onMeasured = vm::onSurfaceMeasured,
    )
}

@Composable
private fun TerminalContent(
    state: TerminalsUiState,
    onBack: () -> Unit,
    onDraftChanged: (String) -> Unit,
    onSend: () -> Unit,
    onKey: (AccessoryKey) -> Unit,
    onToggleModifier: (StickyModifier) -> Unit,
    onRetry: () -> Unit,
    onSelectTab: (ULong) -> Unit,
    onNewTab: () -> Unit,
    onCloseTab: (ULong) -> Unit,
    onOpenSwitcher: () -> Unit,
    onCloseSwitcher: () -> Unit,
    onMeasured: (Int, Int) -> Unit,
) {
    Box(modifier = Modifier.fillMaxSize()) {
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            // Insets are handled per-element here: the composer has to sit exactly
            // on top of the IME, and letting Scaffold pad the whole content would
            // lift the output surface away from the keyboard instead.
            contentWindowInsets = WindowInsets(0, 0, 0, 0),
            topBar = {
                TerminalHeader(
                    state = state,
                    onBack = onBack,
                    onOpenSwitcher = onOpenSwitcher,
                )
            },
        ) { inner ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(top = inner.calculateTopPadding()),
            ) {
                if (state.tabs.isNotEmpty()) {
                    TerminalTabRow(
                        tabs = state.tabs,
                        activeId = state.activeId,
                        onSelect = onSelectTab,
                        onNew = onNewTab,
                    )
                    HairlineDivider()
                }

                Box(modifier = Modifier.weight(1f)) {
                    val failure = state.error
                    val active = state.active
                    when {
                        state.spawning && active == null -> SpawningState()

                        failure != null && active == null -> ErrorState(
                            title = failure.title,
                            body = failure.detail,
                            actionLabel = failure.actionLabel.takeIf {
                                failure.action == ErrorAction.Retry
                            },
                            onAction = onRetry,
                        )

                        active == null -> EmptyState(
                            icon = Icons.Rounded.Terminal,
                            title = "No terminals open",
                            body = "Your machine keeps every terminal you open running, even " +
                                "while the app is closed. Start one to see it here.",
                            actionLabel = "Open a terminal",
                            onAction = onNewTab,
                        )

                        else -> TerminalOutput(tab = active, onMeasured = onMeasured)
                    }
                }

                // A banner rather than a takeover: the screen you were looking at
                // is still valid, and hiding it behind an error would lose output.
                val failure = state.error
                if (failure != null && state.active != null) {
                    HairlineDivider()
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(MaterialTheme.semantic.dangerContainer)
                            .padding(horizontal = Space.l, vertical = Space.s),
                    ) {
                        Text(
                            text = "${failure.title}. ${failure.detail}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.semantic.danger,
                        )
                    }
                }

                HairlineDivider()

                AccessoryRow(
                    sticky = state.sticky,
                    onKey = onKey,
                    onToggleModifier = onToggleModifier,
                )

                Composer(
                    draft = state.draft,
                    sticky = state.sticky,
                    enabled = state.active?.running == true,
                    onDraftChanged = onDraftChanged,
                    onSend = onSend,
                )
            }
        }

        if (state.switcherOpen) {
            TerminalSwitcher(
                tabs = state.tabs,
                activeId = state.activeId,
                onSelect = onSelectTab,
                onCloseTab = onCloseTab,
                onDismiss = onCloseSwitcher,
            )
        }
    }
}

@Composable
private fun SpawningState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator(
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(22.dp),
            )
            Text(
                text = "Spawning a PTY on your machine",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.semantic.textLow,
                modifier = Modifier.padding(top = Space.l),
            )
        }
    }
}

@Composable
private fun TerminalHeader(
    state: TerminalsUiState,
    onBack: () -> Unit,
    onOpenSwitcher: () -> Unit,
) {
    val active = state.active
    Column(modifier = Modifier.statusBarsPadding()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = Space.s, vertical = Space.xs),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack, modifier = Modifier.size(48.dp)) {
                Icon(
                    imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                    contentDescription = "Back",
                    tint = MaterialTheme.colorScheme.onBackground,
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = active?.let { "pty ${it.ptyId}" } ?: "Terminal",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                MonoText(text = active?.cwd ?: "no terminal open")
            }
            HSpace(Space.s)
            Text(
                text = "kept by your machine",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.semantic.textFaint,
            )
            IconButton(onClick = onOpenSwitcher, modifier = Modifier.size(48.dp)) {
                Icon(
                    imageVector = Icons.Rounded.ViewAgenda,
                    contentDescription = "All terminals, ${state.tabs.size} open" +
                        if (state.unreadCount > 0) ", ${state.unreadCount} with new output" else "",
                    tint = if (state.unreadCount > 0) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.semantic.textLow
                    },
                    modifier = Modifier.size(20.dp),
                )
            }
        }
        HairlineDivider()
    }
}

/**
 * The output surface.
 *
 * A text list, not the Canvas glyph-atlas renderer: this milestone ships a
 * rendered screen as a string (`TerminalFrame.screen`), and the cell-diff
 * protocol plus the atlas arrive with M2 (§13).
 *
 * It is also where the terminal's real geometry is discovered. The daemon spawns
 * every PTY at 80x24, so the columns and rows this surface can actually hold are
 * measured from one monospace glyph and reported upward exactly once per size.
 */
@Composable
private fun TerminalOutput(tab: TerminalTab, onMeasured: (Int, Int) -> Unit) {
    val lines = remember(tab.screen) { tab.screen.split('\n') }
    val listState = rememberLazyListState()
    val horizontal = rememberScrollState()
    val measurer = rememberTextMeasurer()
    val density = LocalDensity.current

    // Follow the tail. A terminal that does not auto-scroll is unusable, and a
    // phone has no spare screen height to notice you have fallen behind.
    LaunchedEffect(tab.ptyId, lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }

    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        // One glyph is enough because the family is monospace; ten of them keeps
        // the rounding error under a tenth of a column.
        val cellWidth = remember(measurer, density) {
            measurer.measure(text = SAMPLE, style = Mono.body).size.width / SAMPLE.length.toFloat()
        }
        val lineHeight = with(density) { Mono.body.lineHeight.toPx() }
        val usableWidth = with(density) { (maxWidth - Space.m * 2).toPx() }
        val usableHeight = with(density) { (maxHeight - Space.s * 2).toPx() }

        val cols = (usableWidth / cellWidth).toInt()
        val rows = (usableHeight / lineHeight).toInt()

        LaunchedEffect(tab.ptyId, cols, rows) {
            if (cols > 0 && rows > 0) onMeasured(cols, rows)
        }

        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                .semantics { contentDescription = "Terminal output, ${lines.size} lines" },
            contentPadding = PaddingValues(horizontal = Space.m, vertical = Space.s),
        ) {
            itemsIndexed(lines, key = { index, _ -> index }) { _, line ->
                Text(
                    text = line.ifEmpty { " " },
                    style = Mono.body,
                    color = MaterialTheme.colorScheme.onSurface,
                    softWrap = false,
                    maxLines = 1,
                    modifier = Modifier.horizontalScroll(horizontal),
                )
            }
        }
    }
}

@Composable
private fun Composer(
    draft: String,
    sticky: StickyModifier,
    enabled: Boolean,
    onDraftChanged: (String) -> Unit,
    onSend: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainer)
            // Chained deliberately: each modifier consumes the inset it applies,
            // so the total is max(nav bar, IME), not their sum.
            .navigationBarsPadding()
            .imePadding()
            .padding(horizontal = Space.s, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        TextField(
            value = draft,
            onValueChange = onDraftChanged,
            enabled = enabled,
            modifier = Modifier.weight(1f),
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
            textStyle = Mono.body,
            placeholder = {
                Text(
                    text = when (sticky) {
                        StickyModifier.None -> "type a command"
                        StickyModifier.Ctrl -> "Ctrl armed — next key goes to the shell"
                        StickyModifier.Alt -> "Alt armed — next key goes to the shell"
                    },
                    style = Mono.body,
                    color = MaterialTheme.semantic.textFaint,
                )
            },
            colors = TextFieldDefaults.colors(
                focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLowest,
                unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLowest,
                disabledContainerColor = MaterialTheme.colorScheme.surfaceContainerLowest,
                focusedIndicatorColor = Color.Transparent,
                unfocusedIndicatorColor = Color.Transparent,
                disabledIndicatorColor = Color.Transparent,
                cursorColor = MaterialTheme.colorScheme.primary,
            ),
            keyboardOptions = KeyboardOptions(
                // Autocorrect on a command line is actively hostile.
                autoCorrectEnabled = false,
                capitalization = KeyboardCapitalization.None,
                imeAction = ImeAction.Send,
            ),
            keyboardActions = KeyboardActions(onSend = { onSend() }),
        )

        IconButton(
            onClick = onSend,
            enabled = enabled,
            modifier = Modifier.size(48.dp),
        ) {
            Icon(
                imageVector = Icons.AutoMirrored.Rounded.Send,
                contentDescription = "Send to the terminal",
                tint = if (enabled) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.semantic.textFaint
                },
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

private const val SAMPLE = "MMMMMMMMMM"

// --- previews ---------------------------------------------------------------

@Preview(name = "Terminal · tabs", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun TerminalPreview() {
    GoNomadTheme {
        TerminalContent(
            state = TerminalsUiState(
                tabs = previewTabs,
                activeId = 1uL,
                draft = "cargo test",
            ),
            onBack = {},
            onDraftChanged = {},
            onSend = {},
            onKey = {},
            onToggleModifier = {},
            onRetry = {},
            onSelectTab = {},
            onNewTab = {},
            onCloseTab = {},
            onOpenSwitcher = {},
            onCloseSwitcher = {},
            onMeasured = { _, _ -> },
        )
    }
}

@Preview(name = "Terminal · Ctrl armed", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun TerminalCtrlPreview() {
    GoNomadTheme {
        TerminalContent(
            state = TerminalsUiState(
                tabs = previewTabs,
                activeId = 2uL,
                sticky = StickyModifier.Ctrl,
            ),
            onBack = {},
            onDraftChanged = {},
            onSend = {},
            onKey = {},
            onToggleModifier = {},
            onRetry = {},
            onSelectTab = {},
            onNewTab = {},
            onCloseTab = {},
            onOpenSwitcher = {},
            onCloseSwitcher = {},
            onMeasured = { _, _ -> },
        )
    }
}

@Preview(name = "Terminal · none open", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun TerminalEmptyPreview() {
    GoNomadTheme {
        TerminalContent(
            state = TerminalsUiState(),
            onBack = {},
            onDraftChanged = {},
            onSend = {},
            onKey = {},
            onToggleModifier = {},
            onRetry = {},
            onSelectTab = {},
            onNewTab = {},
            onCloseTab = {},
            onOpenSwitcher = {},
            onCloseSwitcher = {},
            onMeasured = { _, _ -> },
        )
    }
}
