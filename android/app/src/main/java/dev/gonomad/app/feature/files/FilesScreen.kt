package dev.gonomad.app.feature.files

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.FolderOff
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.gonomad.app.ffi.DirEntry
import dev.gonomad.app.ffi.EntryKind
import dev.gonomad.app.ui.common.ErrorAction
import dev.gonomad.app.ui.common.formatBytes
import dev.gonomad.app.ui.common.relativeTime
import dev.gonomad.app.ui.common.scopedViewModel
import dev.gonomad.app.ui.components.EmptyState
import dev.gonomad.app.ui.components.ErrorState
import dev.gonomad.app.ui.components.FileListSkeleton
import dev.gonomad.app.ui.components.HSpace
import dev.gonomad.app.ui.components.HairlineDivider
import dev.gonomad.app.ui.theme.GoNomadTheme
import dev.gonomad.app.ui.theme.Mono
import dev.gonomad.app.ui.theme.Space
import dev.gonomad.app.ui.theme.semantic

@Composable
fun FilesScreen(
    root: String,
    onBack: () -> Unit,
    onOpenFile: (String) -> Unit,
    onOpenTerminal: (String) -> Unit,
) {
    // Keyed by root so navigating into a second workspace gets its own tree
    // rather than reusing the first one's cache.
    val vm: FilesViewModel = scopedViewModel(key = "files:$root") { FilesViewModel(it, root) }
    val state by vm.state.collectAsStateWithLifecycle()

    FilesContent(
        state = state,
        onBack = onBack,
        onRefresh = vm::refresh,
        onRetry = vm::retry,
        onToggleHidden = vm::toggleHidden,
        onToggleIgnored = vm::toggleIgnored,
        onNodeClick = { node -> vm.onNodeClicked(node, onOpenFile) },
        onOpenTerminal = { onOpenTerminal(root) },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FilesContent(
    state: FilesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onToggleHidden: () -> Unit,
    onToggleIgnored: () -> Unit,
    onNodeClick: (FileNode) -> Unit,
    onOpenTerminal: () -> Unit,
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            // A custom top bar is not a Material TopAppBar, so the status-bar
            // inset has to be applied here.
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
                    Text(
                        text = "Files",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onBackground,
                        modifier = Modifier.weight(1f),
                    )
                    FilterToggle(
                        on = state.showHidden,
                        onLabel = "Hiding dotfiles",
                        offLabel = "Showing dotfiles",
                        text = "·hidden",
                        onClick = onToggleHidden,
                    )
                    HSpace(Space.xs)
                    FilterToggle(
                        on = state.showIgnored,
                        onLabel = "Hiding gitignored files",
                        offLabel = "Showing gitignored files",
                        text = "ignored",
                        onClick = onToggleIgnored,
                    )
                    IconButton(onClick = onOpenTerminal, modifier = Modifier.size(48.dp)) {
                        Icon(
                            imageVector = Icons.Rounded.Terminal,
                            contentDescription = "Open a terminal here",
                            tint = MaterialTheme.semantic.textLow,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
                Breadcrumb(root = state.root)
                HairlineDivider()
            }
        },
    ) { inner ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner),
        ) {
            val failure = state.error
            when {
                state.loading -> FileListSkeleton(modifier = Modifier.padding(top = Space.m))

                failure != null && state.nodes.isEmpty() -> ErrorState(
                    title = failure.title,
                    body = failure.detail,
                    actionLabel = failure.actionLabel.takeIf {
                        failure.action == ErrorAction.Retry
                    },
                    onAction = onRetry,
                )

                state.isEmpty -> EmptyState(
                    icon = Icons.Rounded.FolderOff,
                    title = "Nothing visible here",
                    body = "This directory is empty, or everything in it is hidden or " +
                        "gitignored. Try the toggles above.",
                )

                else -> PullToRefreshBox(
                    isRefreshing = state.refreshing,
                    onRefresh = onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(bottom = Space.xxl),
                    ) {
                        items(state.nodes, key = { it.path }) { node ->
                            FileRow(node = node, onClick = { onNodeClick(node) })
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun FilterToggle(
    on: Boolean,
    onLabel: String,
    offLabel: String,
    text: String,
    onClick: () -> Unit,
) {
    val container = if (on) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceContainerHigh
    }
    val content = if (on) MaterialTheme.colorScheme.primary else MaterialTheme.semantic.textFaint

    Box(
        modifier = Modifier
            .heightIn(min = 48.dp)
            .clip(RoundedCornerShape(999.dp))
            .clickable(onClick = onClick)
            .clearAndSetSemantics { contentDescription = if (on) onLabel else offLabel },
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(999.dp))
                .background(container)
                .padding(horizontal = Space.m, vertical = 6.dp),
        ) {
            Text(text = text, style = Mono.label, color = content)
        }
    }
}

/**
 * Sticky path header. The tree expands in place rather than pushing a new
 * screen per directory, so this shows where the *root* is; the last segment is
 * accented because that is the thing being listed.
 */
@Composable
private fun Breadcrumb(root: String) {
    val crumbs = root.split('/').filter { it.isNotBlank() }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = Space.l, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        crumbs.forEachIndexed { index, label ->
            if (index > 0) {
                Text(
                    text = " / ",
                    style = Mono.label,
                    color = MaterialTheme.semantic.textFaint,
                )
            }
            Text(
                text = label,
                style = Mono.label,
                color = if (index == crumbs.lastIndex) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.semantic.textLow
                },
            )
        }
    }
}

@Composable
private fun FileRow(node: FileNode, onClick: () -> Unit) {
    val entry = node.entry
    val glyph = glyphFor(entry, node.expanded)
    val dimmed = entry.isGitIgnored || entry.isHidden

    val nameColour = when {
        dimmed -> MaterialTheme.semantic.textFaint
        entry.kind == EntryKind.DIRECTORY -> MaterialTheme.colorScheme.onSurface
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .heightIn(min = 48.dp)
            .padding(end = Space.l),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Indentation guides: a faint rail per depth level reads as structure
        // without a 1 px grid across the whole screen.
        Spacer(Modifier.width(Space.s))
        repeat(node.depth) {
            Box(
                modifier = Modifier
                    .width(Space.l)
                    .heightIn(min = 48.dp)
                    .padding(vertical = 4.dp),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .width(1.dp)
                        .fillMaxSize()
                        .background(MaterialTheme.semantic.hairline),
                )
            }
        }
        Spacer(Modifier.width(Space.s))

        Box(modifier = Modifier.size(18.dp), contentAlignment = Alignment.Center) {
            if (entry.kind == EntryKind.DIRECTORY) {
                if (node.loadingChildren) {
                    CircularProgressIndicator(
                        strokeWidth = 1.5.dp,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(12.dp),
                    )
                } else {
                    val rotation by animateFloatAsState(
                        targetValue = if (node.expanded) 0f else -90f,
                        label = "chevron",
                    )
                    Icon(
                        imageVector = Icons.Rounded.ExpandMore,
                        contentDescription = null,
                        tint = MaterialTheme.semantic.textFaint,
                        modifier = Modifier
                            .size(16.dp)
                            .rotate(rotation),
                    )
                }
            }
        }

        HSpace(Space.s)

        Icon(
            imageVector = glyph.icon,
            contentDescription = null,
            tint = if (dimmed) MaterialTheme.semantic.textFaint else glyph.tint,
            modifier = Modifier.size(18.dp),
        )

        HSpace(Space.m)

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = entry.name,
                style = Mono.body,
                color = nameColour,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val meta = buildList {
                if (entry.kind == EntryKind.FILE) add(formatBytes(entry.sizeBytes))
                entry.modifiedMs?.let { add(relativeTime(it)) }
                if (entry.isGitIgnored) add("gitignored")
            }.filter { it.isNotBlank() }
            if (meta.isNotEmpty()) {
                Text(
                    text = meta.joinToString("  ·  "),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.semantic.textFaint,
                    maxLines = 1,
                )
            }
        }
    }
}

// --- previews ---------------------------------------------------------------

private fun previewEntry(
    name: String,
    kind: EntryKind = EntryKind.FILE,
    size: Long? = 1_204,
    ignored: Boolean = false,
) = DirEntry(
    name = name,
    kind = kind,
    sizeBytes = size?.toULong(),
    modifiedMs = System.currentTimeMillis() - 47 * 60_000L,
    isHidden = name.startsWith("."),
    isGitIgnored = ignored,
)

private val previewNodes = listOf(
    FileNode("/r/crates", previewEntry("crates", EntryKind.DIRECTORY, null), 0, true, false),
    FileNode(
        "/r/crates/gonomad-core",
        previewEntry("gonomad-core", EntryKind.DIRECTORY, null),
        1,
        true,
        false,
    ),
    FileNode("/r/crates/gonomad-core/src", previewEntry("src", EntryKind.DIRECTORY, null), 2, false, true),
    FileNode("/r/crates/gonomad-core/Cargo.toml", previewEntry("Cargo.toml", size = 742), 2, false, false),
    FileNode("/r/target", previewEntry("target", EntryKind.DIRECTORY, null, ignored = true), 0, false, false),
    FileNode("/r/Cargo.toml", previewEntry("Cargo.toml", size = 1_486), 0, false, false),
    FileNode("/r/README.md", previewEntry("README.md", size = 24_812), 0, false, false),
    FileNode("/r/logo.png", previewEntry("logo.png", size = 38_402), 0, false, false),
)

@Preview(name = "Files · tree", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun FilesPreview() {
    GoNomadTheme {
        FilesContent(
            state = FilesUiState(
                root = "C:/Users/dev/src/gonomad",
                loading = false,
                nodes = previewNodes,
                showIgnored = true,
            ),
            onBack = {},
            onRefresh = {},
            onRetry = {},
            onToggleHidden = {},
            onToggleIgnored = {},
            onNodeClick = {},
            onOpenTerminal = {},
        )
    }
}

@Preview(name = "Files · loading", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun FilesLoadingPreview() {
    GoNomadTheme {
        FilesContent(
            state = FilesUiState(root = "C:/Users/dev/src/gonomad", loading = true),
            onBack = {},
            onRefresh = {},
            onRetry = {},
            onToggleHidden = {},
            onToggleIgnored = {},
            onNodeClick = {},
            onOpenTerminal = {},
        )
    }
}
