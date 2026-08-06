package dev.gonomad.app.feature.viewer

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.ContentCut
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.gonomad.ffi.FileContent
import dev.gonomad.ffi.GonomadException
import dev.gonomad.app.ui.common.ErrorAction
import dev.gonomad.app.ui.common.scopedViewModel
import dev.gonomad.app.ui.common.toPresentation
import dev.gonomad.app.ui.components.CodeSkeleton
import dev.gonomad.app.ui.components.ErrorState
import dev.gonomad.app.ui.components.HSpace
import dev.gonomad.app.ui.components.HairlineDivider
import dev.gonomad.app.ui.components.MonoText
import dev.gonomad.app.ui.theme.GoNomadTheme
import dev.gonomad.app.ui.theme.Mono
import dev.gonomad.app.ui.theme.SemanticColors
import dev.gonomad.app.ui.theme.Space
import dev.gonomad.app.ui.theme.semantic

@Composable
fun ViewerScreen(path: String, onBack: () -> Unit) {
    val vm: ViewerViewModel = scopedViewModel(key = "viewer:$path") { ViewerViewModel(it, path) }
    val state by vm.state.collectAsStateWithLifecycle()

    ViewerContent(state = state, onBack = onBack, onRetry = vm::retry)
}

@Composable
private fun ViewerContent(
    state: ViewerUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
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
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = state.fileName,
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onBackground,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        MonoText(text = state.directory)
                    }
                    HSpace(Space.s)
                    // Read-only is a fact about this milestone, not a mode the
                    // user chose, so it is stated rather than implied.
                    Text(
                        text = "read-only",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.semantic.textFaint,
                        modifier = Modifier.padding(end = Space.m),
                    )
                }
                HairlineDivider()
            }
        },
    ) { inner ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .background(MaterialTheme.colorScheme.surfaceContainerLowest),
        ) {
            val failure = state.error
            when {
                state.loading -> CodeSkeleton()

                failure != null -> ErrorState(
                    title = failure.title,
                    body = failure.detail,
                    actionLabel = failure.actionLabel.takeIf { failure.action == ErrorAction.Retry },
                    onAction = onRetry,
                )

                else -> CodeBody(state = state)
            }
        }
    }
}

@Composable
private fun CodeBody(state: ViewerUiState) {
    val palette = MaterialTheme.semantic
    val base = MaterialTheme.colorScheme.onSurface
    val horizontal = rememberScrollState()

    // Gutter width scales with the line count so a 4-digit file does not push
    // the code sideways on every row.
    val gutterWidth = when {
        state.lines.size >= 10_000 -> 52.dp
        state.lines.size >= 1_000 -> 44.dp
        else -> 36.dp
    }

    Column(modifier = Modifier.fillMaxSize()) {
        val content = state.content
        if (content != null && content.truncated) {
            TruncationBanner()
        }

        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth(),
            contentPadding = PaddingValues(vertical = Space.s),
        ) {
            itemsIndexed(
                items = state.lines,
                // Index is the only stable identity a plain line has; content
                // repeats constantly in source files.
                key = { index, _ -> index },
            ) { index, line ->
                CodeLine(
                    number = index + 1,
                    line = line,
                    gutterWidth = gutterWidth,
                    horizontal = horizontal,
                    palette = palette,
                    base = base,
                )
            }
        }

        if (content != null) {
            HairlineDivider()
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceContainer)
                    .padding(horizontal = Space.l, vertical = Space.s),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                MonoText(text = "${state.lines.size} lines")
                MonoText(text = content.contentHash, modifier = Modifier.weight(1f, fill = false))
            }
        }
    }
}

@Composable
private fun CodeLine(
    number: Int,
    line: String,
    gutterWidth: Dp,
    horizontal: ScrollState,
    palette: SemanticColors,
    base: Color,
) {
    // Every row shares one ScrollState, so the gutter stays pinned while the
    // code pans — the behaviour you want from a code view, and impossible if
    // each row scrolled independently.
    val annotated = remember(line) { CodeTokens.highlight(line, palette, base) }

    Row(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = number.toString(),
            style = Mono.gutter,
            color = palette.textFaint,
            modifier = Modifier
                .width(gutterWidth)
                .padding(end = Space.s),
        )
        Text(
            text = annotated,
            style = Mono.body,
            maxLines = 1,
            softWrap = false,
            modifier = Modifier
                .weight(1f)
                .horizontalScroll(horizontal)
                .padding(end = Space.l),
        )
    }
}

@Composable
private fun TruncationBanner() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.semantic.warnContainer)
            .padding(horizontal = Space.l, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Rounded.ContentCut,
            contentDescription = null,
            tint = MaterialTheme.semantic.warn,
            modifier = Modifier.size(16.dp),
        )
        HSpace(Space.m)
        Text(
            text = "Truncated at the daemon's read cap. The rest of this file was never sent.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.semantic.warn,
        )
    }
}

// --- previews ---------------------------------------------------------------

private val previewSource = """
    //! Frame layout and CBOR codec.

    pub const MAX_FRAME: usize = 4 * 1024 * 1024;

    pub fn encode<T: Serialize>(kind: Kind, value: &T) -> Result<Bytes, CodecError> {
        let mut payload = Vec::with_capacity(256);
        ciborium::into_writer(value, &mut payload).expect("serialise into Vec cannot fail");

        let len = payload.len() + 1;
        if len > MAX_FRAME {
            return Err(CodecError::TooLarge(len));
        }

        let mut out = BytesMut::with_capacity(HEADER + payload.len());
        out.put_u32(len as u32);
        out.put_u8(kind as u8);
        out.put_slice(&payload);
        Ok(out.freeze())
    }
""".trimIndent()

@Preview(name = "Viewer · code", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun ViewerPreview() {
    GoNomadTheme {
        ViewerContent(
            state = ViewerUiState(
                path = "C:/Users/dev/src/gonomad/crates/gonomad-proto/src/codec.rs",
                loading = false,
                content = FileContent(
                    path = "C:/Users/dev/src/gonomad/crates/gonomad-proto/src/codec.rs",
                    text = previewSource,
                    contentHash = "blake3:9f2c1ab740de55c1",
                    truncated = false,
                ),
                lines = previewSource.lines(),
            ),
            onBack = {},
            onRetry = {},
        )
    }
}

@Preview(name = "Viewer · denied", showBackground = true, backgroundColor = 0xFF0E1116)
@Composable
private fun ViewerDeniedPreview() {
    GoNomadTheme {
        ViewerContent(
            state = ViewerUiState(
                path = "C:/Users/dev/src/atlas-api/.env",
                loading = false,
                error = GonomadException.Denied("fs:secrets").toPresentation(),
            ),
            onBack = {},
            onRetry = {},
        )
    }
}
