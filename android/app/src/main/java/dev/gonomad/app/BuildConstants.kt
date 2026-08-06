package dev.gonomad.app

/**
 * Version strings shown on the About card.
 *
 * Hand-written rather than read from `BuildConfig`, because `buildConfig` is
 * off for this module and generating a whole class for two strings is not worth
 * the build-time cost. Keep in step with `app/build.gradle.kts`.
 */
object BuildConstants {
    const val VERSION_NAME = "0.1.0-alpha01"

    /** The `gonomad/1` ALPN the daemon requires (ARCHITECTURE.md 10.4). */
    const val PROTOCOL_VERSION = "gonomad/1"
}
