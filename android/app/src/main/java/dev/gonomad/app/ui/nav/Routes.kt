package dev.gonomad.app.ui.nav

import kotlinx.serialization.Serializable

/**
 * Type-safe Navigation-Compose routes (ARCHITECTURE.md 6.1).
 *
 * Paths travel as arguments. Navigation URL-encodes string arguments, so the
 * `/` and `:` in `C:/Users/dev/src/...` survive the round trip without any
 * escaping at the call site.
 */
@Serializable
object PairRoute

@Serializable
object HomeRoute

@Serializable
data class FilesRoute(val path: String)

@Serializable
data class ViewerRoute(val path: String)

@Serializable
data class TerminalRoute(val cwd: String)

@Serializable
object SettingsRoute
