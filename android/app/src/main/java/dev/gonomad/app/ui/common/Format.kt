package dev.gonomad.app.ui.common

import java.util.Locale
import kotlin.math.abs

/** "just now", "12 min ago", "3 days ago". Null-safe, so callers stay flat. */
fun relativeTime(epochMs: Long?, now: Long = System.currentTimeMillis()): String {
    if (epochMs == null) return "unknown"
    val delta = now - epochMs
    val ago = delta >= 0
    val d = abs(delta)
    val text = when {
        d < 45_000 -> return if (ago) "just now" else "in a moment"
        d < 90_000 -> "1 min"
        d < 60 * 60_000 -> "${d / 60_000} min"
        d < 2 * 60 * 60_000 -> "1 hour"
        d < 24 * 60 * 60_000 -> "${d / (60 * 60_000)} hours"
        d < 48 * 60 * 60_000 -> "1 day"
        d < 30L * 24 * 60 * 60_000 -> "${d / (24 * 60 * 60_000)} days"
        else -> "${d / (30L * 24 * 60 * 60_000)} months"
    }
    return if (ago) "$text ago" else "in $text"
}

/** Binary-ish sizes the way developers read them: 1.4 kB, 39 MB. */
fun formatBytes(bytes: ULong?): String {
    if (bytes == null) return ""
    val b = bytes.toDouble()
    return when {
        b < 1_000 -> "${bytes} B"
        b < 1_000_000 -> String.format(Locale.UK, "%.1f kB", b / 1_000)
        b < 1_000_000_000 -> String.format(Locale.UK, "%.1f MB", b / 1_000_000)
        else -> String.format(Locale.UK, "%.2f GB", b / 1_000_000_000)
    }
}
