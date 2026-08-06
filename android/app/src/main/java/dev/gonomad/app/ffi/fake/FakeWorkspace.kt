package dev.gonomad.app.ffi.fake

import dev.gonomad.ffi.DirEntry
import dev.gonomad.ffi.EntryKind

/**
 * Canned filesystem for [FakeGonomadClient].
 *
 * Two roots so the workspace picker is not a degenerate list of one: the
 * GoNomad repo itself (Rust + Android) and a small TypeScript service. Paths
 * use forward slashes even though the daemon is Windows-first, matching how
 * the protocol normalises them.
 *
 * Deliberately includes the awkward cases the UI must handle: hidden files, a
 * denylisted `.env`, a binary file, and a file large enough to come back
 * truncated.
 *
 * `isGitIgnored` is `false` on every entry, matching the real `fs.list`, which
 * does not carry the flag until M3. The fake reports what the daemon reports;
 * inventing ignore data here would let a UI that dims tracked files pass review.
 */
internal object FakeWorkspace {

    const val ROOT_GONOMAD = "C:/Users/dev/src/gonomad"
    const val ROOT_ATLAS = "C:/Users/dev/src/atlas-api"

    val roots = listOf(ROOT_GONOMAD, ROOT_ATLAS)

    /** Anchor so "modified 12 minutes ago" stays true for the whole session. */
    private val now = System.currentTimeMillis()

    private const val MINUTE = 60_000L
    private const val HOUR = 60 * MINUTE
    private const val DAY = 24 * HOUR

    private fun dir(
        name: String,
        modifiedAgo: Long = 2 * HOUR,
        hidden: Boolean = name.startsWith("."),
    ) = DirEntry(
        name = name,
        kind = EntryKind.DIRECTORY,
        sizeBytes = null,
        modifiedMs = now - modifiedAgo,
        isHidden = hidden,
        isGitIgnored = false,
    )

    private fun file(
        name: String,
        size: Long,
        modifiedAgo: Long = 3 * HOUR,
        hidden: Boolean = name.startsWith("."),
    ) = DirEntry(
        name = name,
        kind = EntryKind.FILE,
        sizeBytes = size.toULong(),
        modifiedMs = now - modifiedAgo,
        isHidden = hidden,
        isGitIgnored = false,
    )

    private fun link(name: String) = DirEntry(
        name = name,
        kind = EntryKind.SYMLINK,
        sizeBytes = null,
        modifiedMs = now - 9 * DAY,
        isHidden = false,
        isGitIgnored = false,
    )

    /** Directory path -> its children, already in daemon sort order. */
    val dirs: Map<String, List<DirEntry>> = mapOf(
        ROOT_GONOMAD to listOf(
            dir(".github", modifiedAgo = 6 * DAY),
            dir("android", modifiedAgo = 11 * MINUTE),
            dir("crates", modifiedAgo = 48 * MINUTE),
            dir("docs", modifiedAgo = 2 * HOUR),
            dir("target", modifiedAgo = 9 * MINUTE),
            file(".gitignore", 612, 5 * DAY),
            file("ARCHITECTURE.md", 148_390, 3 * HOUR),
            file("Cargo.lock", 91_244, 47 * MINUTE),
            file("Cargo.toml", 1_486, 47 * MINUTE),
            file("LICENSE", 11_357, 21 * DAY),
            file("README.md", 24_812, 4 * HOUR),
            file("logo.png", 38_402, 21 * DAY),
            file("plan.md", 39_115, 26 * HOUR),
        ),
        "$ROOT_GONOMAD/.github" to listOf(
            dir("workflows", modifiedAgo = 6 * DAY, hidden = false),
        ),
        "$ROOT_GONOMAD/.github/workflows" to listOf(
            file("ci.yml", 3_902, 6 * DAY),
            file("release.yml", 2_118, 12 * DAY),
        ),
        "$ROOT_GONOMAD/android" to listOf(
            dir("app", modifiedAgo = 11 * MINUTE),
            dir("gradle", modifiedAgo = 40 * MINUTE),
            file("build.gradle.kts", 227, 40 * MINUTE),
            file("settings.gradle.kts", 532, 40 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app" to listOf(
            dir("build", modifiedAgo = 4 * MINUTE),
            dir("src", modifiedAgo = 11 * MINUTE),
            file("build.gradle.kts", 2_744, 33 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src" to listOf(
            dir("main", modifiedAgo = 11 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main" to listOf(
            dir("java", modifiedAgo = 11 * MINUTE),
            dir("res", modifiedAgo = 26 * MINUTE),
            file("AndroidManifest.xml", 1_602, 26 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main/java" to listOf(
            dir("dev", modifiedAgo = 11 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main/java/dev" to listOf(
            dir("gonomad", modifiedAgo = 11 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main/java/dev/gonomad" to listOf(
            dir("app", modifiedAgo = 11 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main/java/dev/gonomad/app" to listOf(
            dir("ffi", modifiedAgo = 11 * MINUTE),
            dir("ui", modifiedAgo = 14 * MINUTE),
            file("MainActivity.kt", 1_940, 11 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main/java/dev/gonomad/app/ffi" to listOf(
            file("ClientProvider.kt", 2_640, 11 * MINUTE),
            file("TerminalsRepository.kt", 7_318, 11 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main/java/dev/gonomad/app/ui" to listOf(
            dir("theme", modifiedAgo = 14 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main/java/dev/gonomad/app/ui/theme" to listOf(
            file("Theme.kt", 5_209, 14 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main/res" to listOf(
            dir("values", modifiedAgo = 26 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/app/src/main/res/values" to listOf(
            file("strings.xml", 148, 26 * MINUTE),
            file("themes.xml", 704, 26 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/gradle" to listOf(
            dir("wrapper", modifiedAgo = 40 * MINUTE),
            file("libs.versions.toml", 2_401, 40 * MINUTE),
        ),
        "$ROOT_GONOMAD/android/gradle/wrapper" to listOf(
            file("gradle-wrapper.jar", 43_705, 40 * MINUTE),
            file("gradle-wrapper.properties", 386, 40 * MINUTE),
        ),
        "$ROOT_GONOMAD/crates" to listOf(
            dir("gonomad-core", modifiedAgo = 48 * MINUTE),
            dir("gonomad-policy", modifiedAgo = 3 * HOUR),
            dir("gonomad-proto", modifiedAgo = 52 * MINUTE),
            dir("gonomad-store", modifiedAgo = 19 * HOUR),
        ),
        "$ROOT_GONOMAD/crates/gonomad-core" to listOf(
            dir("src", modifiedAgo = 48 * MINUTE),
            dir("tests", modifiedAgo = 5 * HOUR),
            file("Cargo.toml", 742, 2 * DAY),
        ),
        "$ROOT_GONOMAD/crates/gonomad-core/src" to listOf(
            file("identity.rs", 4_318, 5 * HOUR),
            file("lib.rs", 892, 2 * DAY),
            file("pairing.rs", 7_204, 48 * MINUTE),
            file("sas.rs", 2_961, 3 * HOUR),
        ),
        "$ROOT_GONOMAD/crates/gonomad-core/tests" to listOf(
            file("pairing_roundtrip.rs", 3_106, 5 * HOUR),
        ),
        "$ROOT_GONOMAD/crates/gonomad-policy" to listOf(
            dir("src", modifiedAgo = 3 * HOUR),
            file("Cargo.toml", 588, 4 * DAY),
        ),
        "$ROOT_GONOMAD/crates/gonomad-policy/src" to listOf(
            file("capability.rs", 6_120, 3 * HOUR),
            file("denylist.rs", 3_884, 3 * HOUR),
            file("lib.rs", 1_022, 4 * DAY),
            file("path_guard.rs", 8_449, 7 * HOUR),
        ),
        "$ROOT_GONOMAD/crates/gonomad-proto" to listOf(
            dir("src", modifiedAgo = 52 * MINUTE),
            file("Cargo.toml", 655, 3 * DAY),
        ),
        "$ROOT_GONOMAD/crates/gonomad-proto/src" to listOf(
            file("codec.rs", 5_573, 52 * MINUTE),
            file("error.rs", 2_240, 26 * HOUR),
            file("frame.rs", 4_901, 2 * DAY),
            file("lib.rs", 1_310, 3 * DAY),
        ),
        "$ROOT_GONOMAD/crates/gonomad-store" to listOf(
            dir("migrations", modifiedAgo = 19 * HOUR),
            dir("src", modifiedAgo = 19 * HOUR),
            file("Cargo.toml", 701, 5 * DAY),
        ),
        "$ROOT_GONOMAD/crates/gonomad-store/migrations" to listOf(
            file("0001_init.sql", 2_884, 6 * DAY),
            file("0002_audit_chain.sql", 1_207, 19 * HOUR),
        ),
        "$ROOT_GONOMAD/crates/gonomad-store/src" to listOf(
            file("audit.rs", 5_990, 19 * HOUR),
            file("lib.rs", 1_144, 6 * DAY),
        ),
        "$ROOT_GONOMAD/docs" to listOf(
            file("README.md", 2_004, 3 * DAY),
            file("deployment.md", 9_882, 3 * DAY),
            file("ffi-contract.md", 4_667, 2 * HOUR),
            file("threat-model.md", 18_441, 4 * DAY),
        ),
        "$ROOT_GONOMAD/target" to listOf(
            dir("debug", modifiedAgo = 9 * MINUTE),
            dir("release", modifiedAgo = 3 * DAY),
            file(".rustc_info.json", 1_804, 9 * MINUTE),
        ),
        "$ROOT_GONOMAD/target/debug" to listOf(
            dir("deps", modifiedAgo = 9 * MINUTE),
            file("gonomad.exe", 41_882_112, 9 * MINUTE),
        ),
        "$ROOT_GONOMAD/target/release" to emptyList(),
        "$ROOT_GONOMAD/target/debug/deps" to emptyList(),

        ROOT_ATLAS to listOf(
            dir(".vscode", modifiedAgo = 12 * DAY),
            dir("node_modules", modifiedAgo = 2 * DAY),
            dir("src", modifiedAgo = 22 * MINUTE),
            dir("tests", modifiedAgo = 5 * HOUR),
            file(".env", 341, 8 * DAY),
            file(".env.example", 288, 30 * DAY),
            file(".gitignore", 204, 30 * DAY),
            file("package.json", 1_118, 2 * DAY),
            file("pnpm-lock.yaml", 214_009, 2 * DAY),
            file("tsconfig.json", 604, 30 * DAY),
        ),
        "$ROOT_ATLAS/.vscode" to listOf(
            file("settings.json", 402, 12 * DAY, hidden = false),
        ),
        "$ROOT_ATLAS/node_modules" to emptyList(),
        "$ROOT_ATLAS/src" to listOf(
            dir("db", modifiedAgo = 3 * HOUR),
            dir("routes", modifiedAgo = 22 * MINUTE),
            file("index.ts", 1_842, 22 * MINUTE),
            link("shared"),
        ),
        "$ROOT_ATLAS/src/db" to listOf(
            file("pool.ts", 1_201, 3 * HOUR),
            file("schema.sql", 2_664, 4 * DAY),
        ),
        "$ROOT_ATLAS/src/routes" to listOf(
            file("health.ts", 512, 26 * HOUR),
            file("sessions.ts", 3_318, 22 * MINUTE),
        ),
        "$ROOT_ATLAS/tests" to listOf(
            file("sessions.test.ts", 2_970, 5 * HOUR),
        ),
    )

    /** Paths the daemon would refuse without `fs:secrets` + a live biometric. */
    val denylisted = setOf("$ROOT_ATLAS/.env")

    /** Paths that are not UTF-8; `fs.read` refuses these outright. */
    val binary = setOf(
        "$ROOT_GONOMAD/logo.png",
        "$ROOT_GONOMAD/android/gradle/wrapper/gradle-wrapper.jar",
        "$ROOT_GONOMAD/target/debug/gonomad.exe",
    )

    /** Paths large enough that `fs.read` returns `truncated = true`. */
    val truncated = setOf(
        "$ROOT_GONOMAD/Cargo.lock",
        "$ROOT_ATLAS/pnpm-lock.yaml",
    )

    val files: Map<String, String> = FakeFileBodies.bodies

    /** A stand-in for the CAS baseline hash the daemon would return. */
    fun contentHash(path: String, text: String): String {
        var h = -0x340d631b7bdddcdbL // FNV-1a 64 offset basis
        for (c in path) {
            h = (h xor c.code.toLong()) * 0x100000001b3L
        }
        for (c in text) {
            h = (h xor c.code.toLong()) * 0x100000001b3L
        }
        return "blake3:" + java.lang.Long.toHexString(h).padStart(16, '0').repeat(2).take(32)
    }
}
