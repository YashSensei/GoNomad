package dev.gonomad.app.feature.terminal

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.gonomad.app.ui.common.ErrorAction
import dev.gonomad.app.ui.common.scopedViewModel
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
    val vm: TerminalViewModel = scopedViewModel(key = "pty:$cwd") { TerminalViewModel(it, cwd) }
    val state by vm.state.collectAsStateWithLifecycle()

    TerminalContent(
        state = state,
        onBack = onBack,
        onDraftChanged = vm::onDraftChanged,
        onSend = vm::send,
        onKey = vm::onAccessoryKey,
        onToggleModifier = vm::onToggleModifier,
        onRetry = vm::retry,
    )
}

@Composable
private fun TerminalContent(
    state: TerminalUiState,
    onBack: () -> Unit,
    onDraftChanged: (String) -> Unit,
    onSend: () -> Unit,
    onKey: (AccessoryKey) -> Unit,
    onToggleModifier: (StickyModifier) -> Unit,
    onRetry: () -> Unit,
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        // Insets are handled per-element here: the composer has to sit exactly
        // on top of the IME, and letting Scaffold pad the whole content would
        // lift the output surface away from the keyboard instead.
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = { TerminalHeader(state = state, onBack = onBack) },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(top = inner.calculateTopPadding()),
        ) {
            Box(modifier = Modifier.weight(1f)) {
                val failure = state.error
                when {
                    state.starting -> Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center,
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            CircularProgressIndicator(
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(22.dp),
                            )
                            Text(
                                text = "Spawning a PTY on the daemon",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.semantic.textLow,
                                modifier = Modifier.padding(top = Space.l),
                            )
                        }
                    }

                    failure != null && state.screen.isEmpty() -> ErrorState(
                        title = failure.title,
                        body = failure.detail,
                        actionLabel = failure.actionLabel.takeIf {
                            failure.action == ErrorAction.Retry
                        },
                        onAction = onRetry,
                    )

                    else -> TerminalOutput(screen = state.screen)
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
                enabled = state.ptyId != null,
                onDraftChanged = onDraftChanged,
                onSend = onSend,
            )
        }
    }
}

@Composable
private fun TerminalHeader(state: TerminalUiState, onBack: () -> Unit) {
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
                    text = state.ptyId?.let { "pty $it" } ?: "Terminal",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                MonoText(text = state.cwd)
            }
            HSpace(Space.m)
            Text(
                text = "kept by daemon",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.semantic.textFaint,
                modifier = Modifier.padding(end = Space.m),
            )
        }
        HairlineDivider()
    }
}

/**
 * The output surface.
 *
 * This is a text list, not the Canvas glyph-atlas renderer: M1.5 ships a
 * rendered screen as a string (`TerminalFrame.screen`), and the cell-diff
 * protocol plus the atlas arrive with M2 (ARCHITECTURE.md 13).
 */
@Composable
private fun TerminalOutput(screen: String) {
    val lines = remember(screen) { screen.split('\n') }
    val listState = rememberLazyListState()
    val horizontal = rememberScrollState()

    // Follow the tail. A terminal that does not auto-scroll is unusable, and a
    // phone has no spare screen height to notice you have fallen behind.
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
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
            // Chained deliberately: each modifier consumes the inset it
            // applies, so the total is max(nav bar, IME), not their sum.
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
                        StickyModifier.Ctrl -> "Ctrl armed — next key is modified"
                        StickyModifier.Alt -> "Alt armed — next key is modified"
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

// --- previews ---------------------------------------------------------------

private val previewScreen = """
    Windows PowerShell 7.4.5
    (c) Microsoft Corporation. All rights reserved.

    gonomad: pty 1 attached  ·  transport LAN  ·  scrollback held by the daemon

    PS C:\Users\dev\src\gonomad> git status
    On branch feat/ffi-contract
    Your branch is ahead of 'origin/main' by 3 commits.

    Changes not staged for commit:
            modified:   crates/gonomad-core/src/pairing.rs
            modified:   docs/ffi-contract.md

    Untracked files:
            android/

    PS C:\Users\dev\src\gonomad>
""".trimIndent()

@Preview(name = "Terminal", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun TerminalPreview() {
    GoNomadTheme {
        TerminalContent(
            state = TerminalUiState(
                cwd = "C:/Users/dev/src/gonomad",
                ptyId = 1uL,
                starting = false,
                screen = previewScreen,
                draft = "cargo test",
            ),
            onBack = {},
            onDraftChanged = {},
            onSend = {},
            onKey = {},
            onToggleModifier = {},
            onRetry = {},
        )
    }
}

@Preview(name = "Terminal · Ctrl armed", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun TerminalCtrlPreview() {
    GoNomadTheme {
        TerminalContent(
            state = TerminalUiState(
                cwd = "C:/Users/dev/src/gonomad",
                ptyId = 1uL,
                starting = false,
                screen = previewScreen,
                sticky = StickyModifier.Ctrl,
            ),
            onBack = {},
            onDraftChanged = {},
            onSend = {},
            onKey = {},
            onToggleModifier = {},
            onRetry = {},
        )
    }
}
