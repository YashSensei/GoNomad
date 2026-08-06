package dev.gonomad.app.feature.pair

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.NoPhotography
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.gonomad.app.ui.common.scopedViewModel
import dev.gonomad.app.ui.components.BlendedCard
import dev.gonomad.app.ui.components.HSpace
import dev.gonomad.app.ui.components.MonoText
import dev.gonomad.app.ui.components.VSpace
import dev.gonomad.app.ui.theme.GoNomadTheme
import dev.gonomad.app.ui.theme.Mono
import dev.gonomad.app.ui.theme.Space
import dev.gonomad.app.ui.theme.semantic

@Composable
fun PairScreen(onPaired: () -> Unit) {
    val vm: PairViewModel = scopedViewModel { PairViewModel(it) }
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            vm.startScanning()
        } else {
            // Android does not tell us "never ask again" directly; a denial
            // while the permission is still not held is close enough to warn on.
            vm.onCameraPermissionDenied(permanently = true)
        }
    }

    LaunchedEffect(state.step) {
        if (state.step is PairStep.Paired) onPaired()
    }

    PairContent(
        state = state,
        onRequestScan = {
            val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
            if (granted) vm.startScanning() else permissionLauncher.launch(Manifest.permission.CAMERA)
        },
        onQrScanned = vm::onQrScanned,
        onManualEntry = vm::startManualEntry,
        onManualCodeChanged = vm::onManualCodeChanged,
        onSubmitManual = vm::submitManualCode,
        onConfirmSas = vm::confirmSasMatches,
        onRejectSas = vm::rejectSas,
        onCancel = vm::cancel,
        onOpenAppSettings = {
            context.startActivity(
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.fromParts("package", context.packageName, null),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        },
    )
}

@Composable
private fun PairContent(
    state: PairUiState,
    onRequestScan: () -> Unit,
    onQrScanned: (String) -> Unit,
    onManualEntry: () -> Unit,
    onManualCodeChanged: (String) -> Unit,
    onSubmitManual: () -> Unit,
    onConfirmSas: () -> Unit,
    onRejectSas: () -> Unit,
    onCancel: () -> Unit,
    onOpenAppSettings: () -> Unit,
) {
    when (val step = state.step) {
        is PairStep.Scanning -> ScanningStep(onQrScanned = onQrScanned, onCancel = onCancel)

        is PairStep.ConfirmSas -> SasStep(
            sas = step.sas,
            onConfirm = onConfirmSas,
            onReject = onRejectSas,
        )

        is PairStep.Handshaking -> BusyStep(
            title = "Completing the handshake",
            body = "Running a Noise IKpsk2 exchange with the laptop. Nothing is trusted yet.",
        )

        is PairStep.Committing -> BusyStep(
            title = "Registering this device",
            body = "Storing the daemon's public key. This phone now has a credential of its own.",
        )

        is PairStep.Paired -> BusyStep(
            title = "Paired",
            body = "Opening your machine.",
        )

        is PairStep.ManualEntry -> ManualStep(
            code = state.manualCode,
            onCodeChanged = onManualCodeChanged,
            onSubmit = onSubmitManual,
            onCancel = onCancel,
        )

        is PairStep.Intro -> IntroStep(
            state = state,
            onRequestScan = onRequestScan,
            onManualEntry = onManualEntry,
            onOpenAppSettings = onOpenAppSettings,
        )
    }
}

// --- intro ------------------------------------------------------------------

@Composable
private fun IntroStep(
    state: PairUiState,
    onRequestScan: () -> Unit,
    onManualEntry: () -> Unit,
    onOpenAppSettings: () -> Unit,
) {
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = Space.l, vertical = Space.l),
        ) {
            Text(
                text = ">_",
                style = Mono.key.copy(fontSize = 30.sp),
                color = MaterialTheme.colorScheme.primary,
            )
            VSpace(Space.s)
            Text(
                text = "Pair with your machine",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            VSpace(Space.s)
            Text(
                text = "GoNomad gives this phone a purpose-built interface onto a machine " +
                    "you already own. Your laptop does the work; the phone renders it.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.semantic.textLow,
            )

            VSpace(Space.xl)

            // The honest statement. It is first, it is not collapsed behind a
            // "learn more", and it uses the words from the README: pty:spawn
            // transitively grants arbitrary code execution.
            BlendedCard(color = MaterialTheme.colorScheme.surfaceContainerHigh) {
                Text(
                    text = "What this grants",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                VSpace(Space.m)
                GrantRow(
                    icon = Icons.Rounded.FolderOpen,
                    title = "Read your source",
                    body = "Every file inside the workspace roots you declare on the laptop.",
                )
                VSpace(Space.m)
                GrantRow(
                    icon = Icons.Rounded.Terminal,
                    title = "Run commands as you",
                    body = "A shell can run anything your account can. If you want a " +
                        "genuinely read-only phone, withhold `pty:spawn` at the laptop.",
                )
                VSpace(Space.m)
                GrantRow(
                    icon = Icons.Rounded.Fingerprint,
                    title = "Not your secrets, by default",
                    body = "`.ssh`, `.env`, `*.pem` and friends need a separate capability " +
                        "and a live biometric each time.",
                )
            }

            VSpace(Space.m)

            BlendedCard {
                Text(
                    text = "On the laptop",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                VSpace(Space.s)
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                        .padding(Space.m),
                ) {
                    MonoText(
                        text = "gonomad pair",
                        color = MaterialTheme.colorScheme.primary,
                        style = Mono.body,
                    )
                }
                VSpace(Space.s)
                Text(
                    text = "The QR is valid for 120 seconds and can be used once.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.semantic.textFaint,
                )
            }

            val failure = state.error
            if (failure != null) {
                VSpace(Space.m)
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
                }
            }

            if (state.cameraPermanentlyDenied) {
                VSpace(Space.m)
                BlendedCard(color = MaterialTheme.colorScheme.surfaceContainerHigh) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Rounded.NoPhotography,
                            contentDescription = null,
                            tint = MaterialTheme.semantic.warn,
                            modifier = Modifier.size(20.dp),
                        )
                        HSpace(Space.m)
                        Text(
                            text = "Camera access is off",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                    VSpace(Space.s)
                    Text(
                        text = "You can still pair: type the code the laptop prints under the " +
                            "QR. Nothing about pairing needs the camera.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.semantic.textLow,
                    )
                    TextButton(
                        onClick = onOpenAppSettings,
                        modifier = Modifier.heightIn(min = 48.dp),
                    ) {
                        Text("Open app settings")
                    }
                }
            }

            VSpace(Space.xl)

            Button(
                onClick = onRequestScan,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 56.dp),
                shape = RoundedCornerShape(14.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.QrCodeScanner,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                )
                HSpace(Space.s)
                Text("Scan the QR", style = MaterialTheme.typography.labelLarge)
            }

            TextButton(
                onClick = onManualEntry,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp),
            ) {
                Text("Enter a code instead", color = MaterialTheme.semantic.textLow)
            }
        }
    }
}

@Composable
private fun GrantRow(icon: ImageVector, title: String, body: String) {
    Row {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.semantic.textLow,
            modifier = Modifier
                .padding(top = 2.dp)
                .size(18.dp),
        )
        HSpace(Space.m)
        Column {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = body,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.semantic.textLow,
            )
        }
    }
}

// --- scanning ---------------------------------------------------------------

@Composable
private fun ScanningStep(onQrScanned: (String) -> Unit, onCancel: () -> Unit) {
    Box(modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        QrScannerPreview(onDetected = onQrScanned, modifier = Modifier.fillMaxSize())

        Scaffold(
            containerColor = Color.Transparent,
            topBar = {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(Space.s),
                    horizontalArrangement = Arrangement.End,
                ) {
                    IconButton(onClick = onCancel, modifier = Modifier.size(48.dp)) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = "Cancel pairing",
                            tint = MaterialTheme.colorScheme.onBackground,
                        )
                    }
                }
            },
        ) { inner ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(inner)
                    .padding(Space.l),
                verticalArrangement = Arrangement.Bottom,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                BlendedCard(color = MaterialTheme.colorScheme.surfaceContainerHigh) {
                    Text(
                        text = "Point at the QR on your laptop",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    VSpace(Space.xs)
                    Text(
                        text = "Scan it from the screen, not from a photo — the six digits " +
                            "you confirm next are what makes that difference detectable.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.semantic.textLow,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }
    }
}

// --- SAS --------------------------------------------------------------------

/**
 * The security-critical screen.
 *
 * Yes and No are the same size, the same shape, the same typography, and sit
 * side by side. A visually dominant Yes trains exactly the reflex the SAS
 * exists to prevent (ARCHITECTURE.md 23.3), so the asymmetry that would look
 * "designed" here is the bug.
 */
@Composable
private fun SasStep(sas: String, onConfirm: () -> Unit, onReject: () -> Unit) {
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(horizontal = Space.l),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "Does this match your laptop?",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
            )

            VSpace(Space.xl)

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(20.dp))
                    .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                    .padding(vertical = Space.xl),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = sas,
                    style = Mono.sas,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }

            VSpace(Space.l)

            Text(
                text = "The laptop is showing six digits too. If they differ, someone else " +
                    "is on the other end of this handshake.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.semantic.textLow,
                textAlign = TextAlign.Center,
            )

            VSpace(Space.xl)

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(Space.m),
            ) {
                SasChoice(
                    label = "No, they differ",
                    container = MaterialTheme.colorScheme.surfaceContainerHigh,
                    content = MaterialTheme.semantic.danger,
                    modifier = Modifier.weight(1f),
                    onClick = onReject,
                )
                SasChoice(
                    label = "Yes, they match",
                    container = MaterialTheme.colorScheme.surfaceContainerHigh,
                    content = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                    onClick = onConfirm,
                )
            }
        }
    }
}

@Composable
private fun SasChoice(
    label: String,
    container: Color,
    content: Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    Button(
        onClick = onClick,
        modifier = modifier.height(64.dp),
        shape = RoundedCornerShape(14.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = container,
            contentColor = content,
        ),
        contentPadding = PaddingValues(horizontal = Space.s),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            textAlign = TextAlign.Center,
        )
    }
}

// --- manual entry -----------------------------------------------------------

@Composable
private fun ManualStep(
    code: String,
    onCodeChanged: (String) -> Unit,
    onSubmit: () -> Unit,
    onCancel: () -> Unit,
) {
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(Space.l),
        ) {
            Text(
                text = "Enter the pairing code",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onBackground,
            )
            VSpace(Space.s)
            Text(
                text = "The laptop prints it underneath the QR. It is case-insensitive and " +
                    "expires with the same 120-second window.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.semantic.textLow,
            )
            VSpace(Space.xl)

            OutlinedTextField(
                value = code,
                onValueChange = onCodeChanged,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                textStyle = Mono.body.copy(fontSize = MaterialTheme.typography.titleLarge.fontSize),
                label = { Text("Pairing code") },
                placeholder = { Text("K7QM-4TZP", style = Mono.body) },
                shape = RoundedCornerShape(12.dp),
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.Characters,
                    imeAction = ImeAction.Go,
                ),
            )

            VSpace(Space.l)

            Button(
                onClick = onSubmit,
                enabled = code.length >= 8,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 56.dp),
                shape = RoundedCornerShape(14.dp),
            ) {
                Text("Pair", style = MaterialTheme.typography.labelLarge)
            }

            TextButton(
                onClick = onCancel,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp),
            ) {
                Text("Back", color = MaterialTheme.semantic.textLow)
            }
        }
    }
}

// --- busy -------------------------------------------------------------------

@Composable
private fun BusyStep(title: String, body: String) {
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(Space.xl),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            CircularProgressIndicator(
                color = MaterialTheme.colorScheme.primary,
                strokeWidth = 2.dp,
                modifier = Modifier.size(28.dp),
            )
            VSpace(Space.xl)
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
            )
            VSpace(Space.s)
            Text(
                text = body,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.semantic.textLow,
                textAlign = TextAlign.Center,
            )
        }
    }
}

// --- previews ---------------------------------------------------------------

@Preview(name = "Pair · intro", showBackground = true, backgroundColor = 0xFF0E1116, heightDp = 900)
@Composable
private fun PairIntroPreview() {
    GoNomadTheme {
        PairContent(
            state = PairUiState(),
            onRequestScan = {},
            onQrScanned = {},
            onManualEntry = {},
            onManualCodeChanged = {},
            onSubmitManual = {},
            onConfirmSas = {},
            onRejectSas = {},
            onCancel = {},
            onOpenAppSettings = {},
        )
    }
}

@Preview(name = "Pair · SAS", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun PairSasPreview() {
    GoNomadTheme {
        PairContent(
            state = PairUiState(step = PairStep.ConfirmSas("418 273")),
            onRequestScan = {},
            onQrScanned = {},
            onManualEntry = {},
            onManualCodeChanged = {},
            onSubmitManual = {},
            onConfirmSas = {},
            onRejectSas = {},
            onCancel = {},
            onOpenAppSettings = {},
        )
    }
}

@Preview(name = "Pair · manual", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun PairManualPreview() {
    GoNomadTheme {
        PairContent(
            state = PairUiState(step = PairStep.ManualEntry, manualCode = "K7QM4TZP"),
            onRequestScan = {},
            onQrScanned = {},
            onManualEntry = {},
            onManualCodeChanged = {},
            onSubmitManual = {},
            onConfirmSas = {},
            onRejectSas = {},
            onCancel = {},
            onOpenAppSettings = {},
        )
    }
}
