package dev.gonomad.app.feature.files

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Article
import androidx.compose.material.icons.rounded.DataObject
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Storage
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import dev.gonomad.ffi.DirEntry
import dev.gonomad.ffi.EntryKind
import dev.gonomad.app.ui.theme.semantic

/** Icon plus tint plus the word a screen reader should hear. */
data class FileGlyph(val icon: ImageVector, val tint: Color, val kindLabel: String)

/**
 * Type-aware icons.
 *
 * Tints come from the token palette rather than per-language brand colours, so
 * a directory listing stays one picture instead of a bag of logos.
 */
@Composable
fun glyphFor(entry: DirEntry, expanded: Boolean): FileGlyph {
    val semantic = MaterialTheme.semantic
    val name = entry.name

    if (entry.kind == EntryKind.SYMLINK) {
        return FileGlyph(Icons.Rounded.Link, semantic.synType, "symlink")
    }
    if (entry.kind == EntryKind.DIRECTORY) {
        return FileGlyph(
            icon = if (expanded) Icons.Rounded.FolderOpen else Icons.Rounded.Folder,
            tint = if (expanded) MaterialTheme.colorScheme.primary else semantic.textLow,
            kindLabel = "folder",
        )
    }

    // Whole-name matches first: `Cargo.toml` is a manifest, not "a .toml".
    val byName = when (name.lowercase()) {
        "cargo.toml", "package.json", "build.gradle.kts", "settings.gradle.kts", "pom.xml" ->
            FileGlyph(Icons.Rounded.Settings, semantic.synNumber, "manifest")

        "cargo.lock", "pnpm-lock.yaml", "package-lock.json", "gradle.lockfile" ->
            FileGlyph(Icons.Rounded.Lock, semantic.textFaint, "lockfile")

        else -> null
    }
    if (byName != null) return byName

    return when (name.substringAfterLast('.', "").lowercase()) {
        "rs", "kt", "kts", "java", "go", "swift", "c", "cpp", "h", "py", "rb" ->
            FileGlyph(Icons.Rounded.DataObject, semantic.synKeyword, "source file")

        "ts", "tsx", "js", "jsx", "mjs" ->
            FileGlyph(Icons.Rounded.DataObject, semantic.synNumber, "source file")

        "md", "txt", "adoc", "rst" ->
            FileGlyph(Icons.AutoMirrored.Rounded.Article, semantic.textLow, "document")

        "json", "toml", "yaml", "yml", "xml", "properties", "ini", "cfg" ->
            FileGlyph(Icons.Rounded.Settings, semantic.synString, "configuration")

        "sql" -> FileGlyph(Icons.Rounded.Storage, semantic.synType, "SQL")

        "sh", "bash", "zsh", "ps1", "bat", "cmd", "exe" ->
            FileGlyph(Icons.Rounded.Terminal, semantic.ok, "executable")

        "png", "jpg", "jpeg", "webp", "gif", "svg", "ico" ->
            FileGlyph(Icons.Rounded.Image, semantic.synComment, "image")

        "pem", "key", "env", "crt" ->
            FileGlyph(Icons.Rounded.Lock, semantic.warn, "secret")

        else -> FileGlyph(Icons.Rounded.Description, semantic.textLow, "file")
    }
}
