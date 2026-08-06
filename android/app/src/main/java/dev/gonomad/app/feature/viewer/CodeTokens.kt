package dev.gonomad.app.feature.viewer

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import dev.gonomad.app.ui.theme.SemanticColors

/**
 * A deliberately shallow token pass — comments, strings, numbers, and a small
 * keyword set — not a parser.
 *
 * Real highlighting belongs on the daemon side, where tree-sitter already has
 * the file (ARCHITECTURE.md 6.3 puts the editor in CodeMirror at M3). This is
 * here so a read-only view of code does not look like a wall of grey, and it
 * degrades to plain text on anything it does not recognise.
 */
object CodeTokens {

    private val keywords = setOf(
        // Rust
        "fn", "let", "mut", "pub", "use", "mod", "impl", "struct", "enum", "trait",
        "match", "self", "Self", "crate", "where", "dyn", "async", "await", "move",
        "unsafe", "ref", "as", "const", "static",
        // Kotlin / TS / general
        "val", "var", "fun", "class", "object", "interface", "override", "suspend",
        "import", "package", "private", "internal", "companion", "data", "sealed",
        "function", "export", "default", "type", "extends", "implements", "public",
        "return", "if", "else", "for", "while", "loop", "break", "continue", "in",
        "is", "when", "try", "catch", "finally", "throw", "new", "null", "true",
        "false", "None", "Some", "Ok", "Err", "await",
    )

    private val types = setOf(
        "String", "Int", "Long", "Boolean", "Unit", "Vec", "Option", "Result",
        "u8", "u16", "u32", "u64", "usize", "i32", "i64", "f32", "f64", "bool",
        "str", "List", "Map", "Set", "number", "string", "boolean", "void", "any",
    )

    private val lineCommentPrefixes = listOf("//", "#", "--", ";")

    fun highlight(line: String, palette: SemanticColors, base: Color): AnnotatedString {
        val trimmed = line.trimStart()
        val commentPrefix = lineCommentPrefixes.firstOrNull { trimmed.startsWith(it) }
        if (commentPrefix != null) {
            return AnnotatedString(line, SpanStyle(color = palette.synComment))
        }

        return buildAnnotatedString {
            var i = 0
            while (i < line.length) {
                val c = line[i]
                when {
                    c == '"' || c == '\'' || c == '`' -> {
                        val end = closingQuote(line, i, c)
                        withStyle(SpanStyle(color = palette.synString)) {
                            append(line.substring(i, end))
                        }
                        i = end
                    }

                    c.isDigit() && (i == 0 || !line[i - 1].isLetterOrDigit()) -> {
                        var end = i
                        while (end < line.length && (line[end].isLetterOrDigit() || line[end] == '.' || line[end] == '_')) {
                            end++
                        }
                        withStyle(SpanStyle(color = palette.synNumber)) {
                            append(line.substring(i, end))
                        }
                        i = end
                    }

                    c.isLetter() || c == '_' -> {
                        var end = i
                        while (end < line.length && (line[end].isLetterOrDigit() || line[end] == '_')) {
                            end++
                        }
                        val word = line.substring(i, end)
                        val colour = when {
                            word in keywords -> palette.synKeyword
                            word in types || word.firstOrNull()?.isUpperCase() == true -> palette.synType
                            else -> base
                        }
                        withStyle(SpanStyle(color = colour)) { append(word) }
                        i = end
                    }

                    else -> {
                        withStyle(SpanStyle(color = palette.textLow)) { append(c) }
                        i++
                    }
                }
            }
        }
    }

    /** Returns the index just past the closing quote, or end of line. */
    private fun closingQuote(line: String, start: Int, quote: Char): Int {
        var i = start + 1
        while (i < line.length) {
            if (line[i] == '\\') {
                i += 2
                continue
            }
            if (line[i] == quote) return i + 1
            i++
        }
        return line.length
    }
}
