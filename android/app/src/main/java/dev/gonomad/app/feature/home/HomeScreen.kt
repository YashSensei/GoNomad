package dev.gonomad.app.feature.home

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.HistoryToggleOff
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.gonomad.ffi.ConnState
import dev.gonomad.ffi.DeviceInfo
import dev.gonomad.ffi.Status
import dev.gonomad.app.ui.common.ErrorAction
import dev.gonomad.app.ui.common.relativeTime
import dev.gonomad.app.ui.common.scopedViewModel
import dev.gonomad.app.ui.components.BlendedCard
import dev.gonomad.app.ui.components.ConnectionChip
import dev.gonomad.app.ui.components.EmptyState
import dev.gonomad.app.ui.components.HSpace
import dev.gonomad.app.ui.components.MonoText
import dev.gonomad.app.ui.components.SectionHeader
import dev.gonomad.app.ui.components.ShimmerBlock
import dev.gonomad.app.ui.components.VSpace
import dev.gonomad.app.ui.theme.GoNomadTheme
import dev.gonomad.app.ui.theme.Mono
import dev.gonomad.app.ui.theme.Space
import dev.gonomad.app.ui.theme.semantic

@Composable
fun HomeScreen(
    onOpenFiles: (String) -> Unit,
    onOpenTerminal: (String) -> Unit,
    onOpenFile: (String) -> Unit,
    onOpenSettings: () -> Unit,
) {
    val vm: HomeViewModel = scopedViewModel { HomeViewModel(it) }
    val state by vm.state.collectAsStateWithLifecycle()

    HomeContent(
        state = state,
        onConnect = vm::connect,
        onDisconnect = vm::disconnect,
        onRetry = vm::retry,
        onOpenFiles = onOpenFiles,
        onOpenTerminal = onOpenTerminal,
        onOpenFile = onOpenFile,
        onOpenSettings = onOpenSettings,
    )
}

@Composable
private fun HomeContent(
    state: HomeUiState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onRetry: () -> Unit,
    onOpenFiles: (String) -> Unit,
    onOpenTerminal: (String) -> Unit,
    onOpenFile: (String) -> Unit,
    onOpenSettings: () -> Unit,
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = { HomeHeader(onOpenSettings = onOpenSettings) },
    ) { inner ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner),
            contentPadding = PaddingValues(
                start = Space.l,
                end = Space.l,
                top = Space.s,
                bottom = Space.xxl,
            ),
            verticalArrangement = Arrangement.spacedBy(Space.m),
        ) {
            item(key = "connection") {
                ConnectionCard(
                    state = state,
                    onConnect = onConnect,
                    onDisconnect = onDisconnect,
                )
            }

            // Captured outside the item lambda: a smart cast cannot cross into
            // a deferred, non-inline builder block.
            val failure = state.error
            if (failure != null) {
                item(key = "error") {
                    BlendedCard(color = MaterialTheme.semantic.dangerContainer) {
                        Text(
                            text = failure.title,
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.semantic.danger,
                        )
                        VSpace(Space.xs)
                        Text(
                            text = failure.detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        if (failure.action == ErrorAction.Retry) {
                            TextButton(
                                onClick = onRetry,
                                modifier = Modifier.heightIn(min = 48.dp),
                            ) {
                                Text(failure.actionLabel ?: "Try again")
                            }
                        }
                    }
                }
            }

            item(key = "quick-actions") {
                VSpace(Space.xs)
                QuickActions(
                    enabled = state.connected,
                    primaryRoot = state.workspaces.firstOrNull()?.root,
                    onOpenFiles = onOpenFiles,
                    onOpenTerminal = onOpenTerminal,
                )
            }

            item(key = "workspaces-header") {
                SectionHeader("Workspaces")
            }

            when {
                state.loadingWorkspaces -> {
                    items(2, key = { "ws-skeleton-$it" }) {
                        BlendedCard {
                            ShimmerBlock(width = 130.dp, height = 16.dp)
                            VSpace(Space.s)
                            ShimmerBlock(width = 210.dp, height = 11.dp)
                        }
                    }
                }

                state.workspaces.isEmpty() -> {
                    item(key = "workspaces-empty") {
                        BlendedCard {
                            EmptyState(
                                icon = Icons.Rounded.FolderOpen,
                                title = if (state.connected) "No workspace roots" else "Nothing to show yet",
                                body = if (state.connected) {
                                    "Declare one on the laptop with `gonomad workspace add .` " +
                                        "— the daemon will only ever serve paths inside a root."
                                } else {
                                    "Workspaces load once a session is up."
                                },
                            )
                        }
                    }
                }

                else -> {
                    items(state.workspaces, key = { it.id }) { ws ->
                        WorkspaceRow(
                            card = ws,
                            onOpen = { onOpenFiles(ws.root) },
                            onTerminal = { onOpenTerminal(ws.root) },
                        )
                    }
                }
            }

            item(key = "recents-header") {
                SectionHeader("Recent files")
            }

            if (state.recentFiles.isEmpty()) {
                item(key = "recents-empty") {
                    BlendedCard {
                        EmptyState(
                            icon = Icons.Rounded.HistoryToggleOff,
                            title = "No recent files",
                            body = "Files you open appear here so getting back to work is one tap.",
                        )
                    }
                }
            } else {
                items(state.recentFiles, key = { it }) { path ->
                    RecentFileRow(path = path, onClick = { onOpenFile(path) })
                }
            }
        }
    }
}

@Composable
private fun HomeHeader(onOpenSettings: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            // A custom top bar is not a Material TopAppBar, so nothing applies
            // the status-bar inset for us.
            .statusBarsPadding()
            .padding(start = Space.l, end = Space.s, top = Space.s, bottom = Space.xs),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = ">_",
                style = Mono.key,
                color = MaterialTheme.colorScheme.primary,
            )
            HSpace(Space.s)
            Text(
                text = "GoNomad",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }
        IconButton(onClick = onOpenSettings, modifier = Modifier.size(48.dp)) {
            Icon(
                imageVector = Icons.Rounded.Settings,
                contentDescription = "Settings",
                tint = MaterialTheme.semantic.textLow,
            )
        }
    }
}

@Composable
private fun ConnectionCard(
    state: HomeUiState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    BlendedCard(color = MaterialTheme.colorScheme.surfaceContainer) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            ConnectionChip(status = state.status)
            when {
                state.busy -> Text(
                    text = "Handshaking",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.semantic.textLow,
                )

                state.connected -> TextButton(
                    onClick = onDisconnect,
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Text("Disconnect", color = MaterialTheme.semantic.textLow)
                }

                else -> TextButton(
                    onClick = onConnect,
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Text("Connect")
                }
            }
        }

        VSpace(Space.m)
        Text(
            text = state.daemon?.name ?: "No machine paired",
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
        VSpace(Space.xs)
        MonoText(
            text = state.daemon?.let { "${it.deviceId}  ·  paired ${relativeTime(it.pairedAt)}" }
                ?: "pair a machine to begin",
        )

        if (state.connected) {
            VSpace(Space.m)
            Text(
                text = "The daemon holds your terminals and sessions. Losing signal does " +
                    "not stop anything running there.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.semantic.textFaint,
            )
        }
    }
}

@Composable
private fun QuickActions(
    enabled: Boolean,
    primaryRoot: String?,
    onOpenFiles: (String) -> Unit,
    onOpenTerminal: (String) -> Unit,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(Space.m)) {
        QuickAction(
            icon = Icons.Rounded.FolderOpen,
            label = "Files",
            enabled = enabled && primaryRoot != null,
            modifier = Modifier.weight(1f),
            onClick = { primaryRoot?.let(onOpenFiles) },
        )
        QuickAction(
            icon = Icons.Rounded.Terminal,
            label = "Terminal",
            enabled = enabled && primaryRoot != null,
            modifier = Modifier.weight(1f),
            onClick = { primaryRoot?.let(onOpenTerminal) },
        )
    }
}

@Composable
private fun QuickAction(
    icon: ImageVector,
    label: String,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val tint = if (enabled) MaterialTheme.colorScheme.primary else MaterialTheme.semantic.textFaint
    val labelColour =
        if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.semantic.textFaint

    Column(
        modifier = modifier
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .clickable(enabled = enabled, onClick = onClick)
            .heightIn(min = 88.dp)
            .padding(Space.l),
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null, // the label below is the accessible name
            tint = tint,
            modifier = Modifier.size(22.dp),
        )
        VSpace(Space.s)
        Text(text = label, style = MaterialTheme.typography.titleMedium, color = labelColour)
    }
}

@Composable
private fun WorkspaceRow(
    card: WorkspaceCard,
    onOpen: () -> Unit,
    onTerminal: () -> Unit,
) {
    BlendedCard(onClick = onOpen) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = card.name,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                VSpace(Space.xs)
                MonoText(text = card.root)
            }
            IconButton(onClick = onTerminal, modifier = Modifier.size(48.dp)) {
                Icon(
                    imageVector = Icons.Rounded.Terminal,
                    contentDescription = "Open a terminal in ${card.name}",
                    tint = MaterialTheme.semantic.textLow,
                    modifier = Modifier.size(20.dp),
                )
            }
            Icon(
                imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.semantic.textFaint,
            )
        }
    }
}

@Composable
private fun RecentFileRow(path: String, onClick: () -> Unit) {
    BlendedCard(
        onClick = onClick,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        contentPadding = PaddingValues(horizontal = Space.l, vertical = Space.m),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier.size(28.dp),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Description,
                    contentDescription = null,
                    tint = MaterialTheme.semantic.textLow,
                    modifier = Modifier.size(18.dp),
                )
            }
            HSpace(Space.m)
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = path.substringAfterLast('/'),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                MonoText(text = path.substringBeforeLast('/'))
            }
        }
    }
}

// --- previews ---------------------------------------------------------------

private val previewStatus = Status(
    state = ConnState.CONNECTED,
    daemonName = "DESKTOP-7QK4L1",
    rttMs = 11u,
    transport = "LAN",
)

private val previewDaemon = DeviceInfo(
    deviceId = "7f3a91c2e40b",
    name = "DESKTOP-7QK4L1",
    pairedAt = System.currentTimeMillis() - 3 * 24 * 60 * 60 * 1000L,
    lastSeen = System.currentTimeMillis(),
)

@Preview(name = "Home · connected", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun HomeConnectedPreview() {
    GoNomadTheme {
        HomeContent(
            state = HomeUiState(
                status = previewStatus,
                daemon = previewDaemon,
                workspaces = listOf(
                    WorkspaceCard("C:/Users/dev/src/gonomad", "gonomad"),
                    WorkspaceCard("C:/Users/dev/src/atlas-api", "atlas-api"),
                ),
                recentFiles = listOf(
                    "C:/Users/dev/src/gonomad/crates/gonomad-core/src/pairing.rs",
                    "C:/Users/dev/src/gonomad/Cargo.toml",
                ),
            ),
            onConnect = {},
            onDisconnect = {},
            onRetry = {},
            onOpenFiles = {},
            onOpenTerminal = {},
            onOpenFile = {},
            onOpenSettings = {},
        )
    }
}

@Preview(name = "Home · offline", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun HomeOfflinePreview() {
    GoNomadTheme {
        HomeContent(
            state = HomeUiState(
                status = Status(ConnState.DISCONNECTED, "DESKTOP-7QK4L1", null, null),
                daemon = previewDaemon,
            ),
            onConnect = {},
            onDisconnect = {},
            onRetry = {},
            onOpenFiles = {},
            onOpenTerminal = {},
            onOpenFile = {},
            onOpenSettings = {},
        )
    }
}
