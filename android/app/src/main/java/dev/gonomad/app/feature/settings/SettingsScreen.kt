package dev.gonomad.app.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.LinkOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.gonomad.app.BuildConstants
import dev.gonomad.ffi.ConnState
import dev.gonomad.ffi.DeviceInfo
import dev.gonomad.ffi.Status
import dev.gonomad.app.ui.common.relativeTime
import dev.gonomad.app.ui.common.rememberTerminals
import dev.gonomad.app.ui.common.scopedViewModel
import dev.gonomad.app.ui.components.BlendedCard
import dev.gonomad.app.ui.components.ConnectionChip
import dev.gonomad.app.ui.components.HairlineDivider
import dev.gonomad.app.ui.components.MonoText
import dev.gonomad.app.ui.components.SectionHeader
import dev.gonomad.app.ui.components.VSpace
import dev.gonomad.app.ui.theme.GoNomadTheme
import dev.gonomad.app.ui.theme.Space
import dev.gonomad.app.ui.theme.semantic

@Composable
fun SettingsScreen(onBack: () -> Unit, onUnpaired: () -> Unit) {
    val terminals = rememberTerminals()
    val vm: SettingsViewModel = scopedViewModel { SettingsViewModel(it, terminals) }
    val state by vm.state.collectAsStateWithLifecycle()

    LaunchedEffect(state.unpaired) {
        if (state.unpaired) onUnpaired()
    }

    SettingsContent(
        state = state,
        usingFakeCore = vm.usingFakeCore,
        onBack = onBack,
        onAskUnpair = vm::askToUnpair,
        onDismissUnpair = vm::dismissUnpair,
        onConfirmUnpair = vm::confirmUnpair,
    )
}

@Composable
private fun SettingsContent(
    state: SettingsUiState,
    usingFakeCore: Boolean,
    onBack: () -> Unit,
    onAskUnpair: () -> Unit,
    onDismissUnpair: () -> Unit,
    onConfirmUnpair: () -> Unit,
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
                        text = "Settings",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onBackground,
                    )
                }
                HairlineDivider()
            }
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = Space.l),
            verticalArrangement = Arrangement.spacedBy(Space.s),
        ) {
            SectionHeader("Connection")
            BlendedCard {
                ConnectionChip(status = state.status)
                VSpace(Space.m)
                SettingRow("Transport", state.status.transport ?: "none")
                SettingRow(
                    "Round trip",
                    state.status.rttMs?.let { "$it ms" } ?: "—",
                )
                SettingRow(
                    "State",
                    state.status.state.name.lowercase().replaceFirstChar { it.uppercase() },
                )
            }

            SectionHeader("Paired machine")
            BlendedCard {
                val daemon = state.daemon
                if (daemon == null) {
                    Text(
                        text = "No machine paired",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.semantic.textLow,
                    )
                } else {
                    Text(
                        text = daemon.name,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    VSpace(Space.xs)
                    MonoText(text = daemon.deviceId)
                    VSpace(Space.m)
                    SettingRow("Paired", relativeTime(daemon.pairedAt))
                    SettingRow("Last seen", relativeTime(daemon.lastSeen))
                    VSpace(Space.m)
                    Text(
                        text = "There is no bearer token here. This phone holds an Ed25519 " +
                            "keypair, and the daemon holds its public half — that pair is the " +
                            "whole credential.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.semantic.textFaint,
                    )
                }
            }

            SectionHeader("Appearance")
            BlendedCard {
                SettingRow("Theme", "Dark")
                SettingRow("Dynamic colour", "Off")
                VSpace(Space.s)
                Text(
                    text = "Dark only for now, and wallpaper-derived colour is deliberately " +
                        "off: a developer tool should look the same on every device you " +
                        "hand it to.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.semantic.textFaint,
                )
            }

            SectionHeader("Danger zone")
            BlendedCard(color = MaterialTheme.colorScheme.surfaceContainerHigh) {
                Text(
                    text = "Unpair this phone",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                VSpace(Space.xs)
                Text(
                    text = "Forgets the daemon and wipes the local keys. There is no recovery " +
                        "path — you re-pair from the laptop.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.semantic.textLow,
                )
                VSpace(Space.m)
                Button(
                    onClick = onAskUnpair,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.semantic.dangerContainer,
                        contentColor = MaterialTheme.semantic.danger,
                    ),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.LinkOff,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        text = "Unpair",
                        modifier = Modifier.padding(start = Space.s),
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
            }

            SectionHeader("About")
            BlendedCard {
                SettingRow("Version", BuildConstants.VERSION_NAME)
                SettingRow("Protocol", BuildConstants.PROTOCOL_VERSION)
                SettingRow("Licence", "Apache-2.0")
                SettingRow("Core", if (usingFakeCore) "fake (in-app)" else "gonomad-ffi")
                if (usingFakeCore) {
                    VSpace(Space.m)
                    Text(
                        text = "This build talks to an in-app fake, not a real daemon. Every " +
                            "file, listing, and terminal response you see is canned data. " +
                            "Nothing has left this device.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.semantic.warn,
                    )
                }
            }

            VSpace(Space.xxl)
        }
    }

    if (state.confirmingUnpair) {
        AlertDialog(
            onDismissRequest = onDismissUnpair,
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            title = {
                Text(
                    text = "Unpair from ${state.daemon?.name ?: "this machine"}?",
                    style = MaterialTheme.typography.titleMedium,
                )
            },
            text = {
                Text(
                    text = "The device key is wiped and the daemon will reject this phone " +
                        "until you pair again. Anything running on the laptop keeps running.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.semantic.textLow,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = onConfirmUnpair,
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Text("Unpair", color = MaterialTheme.semantic.danger)
                }
            },
            dismissButton = {
                TextButton(
                    onClick = onDismissUnpair,
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Text("Keep paired", color = MaterialTheme.colorScheme.onSurface)
                }
            },
        )
    }
}

@Composable
private fun SettingRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.semantic.textLow,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.End,
        )
    }
}

// --- previews ---------------------------------------------------------------

@Preview(name = "Settings", showBackground = true, backgroundColor = 0xFF0E1116, heightDp = 1200)
@Composable
private fun SettingsPreview() {
    GoNomadTheme {
        SettingsContent(
            state = SettingsUiState(
                status = Status(ConnState.CONNECTED, "DESKTOP-7QK4L1", 11u, "LAN"),
                daemon = DeviceInfo(
                    deviceId = "7f3a91c2e40b",
                    name = "DESKTOP-7QK4L1",
                    pairedAt = System.currentTimeMillis() - 3 * 24 * 60 * 60 * 1000L,
                    lastSeen = System.currentTimeMillis() - 30_000L,
                ),
            ),
            usingFakeCore = true,
            onBack = {},
            onAskUnpair = {},
            onDismissUnpair = {},
            onConfirmUnpair = {},
        )
    }
}

@Preview(name = "Settings · unpair dialog", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun SettingsUnpairPreview() {
    GoNomadTheme {
        SettingsContent(
            state = SettingsUiState(
                status = Status(ConnState.CONNECTED, "DESKTOP-7QK4L1", 11u, "LAN"),
                daemon = DeviceInfo("7f3a91c2e40b", "DESKTOP-7QK4L1", 0L, null),
                confirmingUnpair = true,
            ),
            usingFakeCore = true,
            onBack = {},
            onAskUnpair = {},
            onDismissUnpair = {},
            onConfirmUnpair = {},
        )
    }
}
