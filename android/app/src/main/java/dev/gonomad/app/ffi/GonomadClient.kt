package dev.gonomad.app.ffi

/**
 * The Rust <-> Kotlin boundary, transcribed from `docs/ffi-contract.md`.
 *
 * This file is the *only* place the app is allowed to describe the core's API.
 * It is deliberately a Kotlin `interface` rather than the `class` shown in the
 * contract so that a fake can stand in while `gonomad-ffi` is being written;
 * the real UniFFI-generated `GonomadClient` class satisfies this interface
 * structurally (same names, same parameter names, same types), so adopting it
 * is an adapter, not a rewrite. See [ClientProvider].
 *
 * Contract rules that are enforced here:
 *  - every call that can touch the network is `suspend` (rule 4);
 *  - errors are the closed [GonomadError] set (rule 3);
 *  - nothing in this package contains a conditional about protocol state
 *    (rule 1) — the fake is the sole exception, and it is not shipped logic.
 */

enum class ConnState { DISCONNECTED, CONNECTING, CONNECTED, UNPAIRED, REVOKED }

data class DeviceInfo(
    val deviceId: String, // hex, short form for display
    val name: String,
    val pairedAt: Long, // unix ms
    val lastSeen: Long?,
)

data class Status(
    val state: ConnState,
    val daemonName: String?, // e.g. "DESKTOP-ABC"
    val rttMs: UInt?,
    val transport: String?, // "LAN" for this slice
)

enum class EntryKind { FILE, DIRECTORY, SYMLINK }

data class DirEntry(
    val name: String,
    val kind: EntryKind,
    val sizeBytes: ULong?,
    val modifiedMs: Long?,
    val isHidden: Boolean,
    val isGitIgnored: Boolean,
)

data class FileContent(
    val path: String,
    val text: String, // UTF-8; binary files are refused
    val contentHash: String, // CAS baseline for a future write
    val truncated: Boolean, // true if the file exceeded the read cap
)

data class TerminalFrame(
    val ptyId: ULong,
    val screen: String, // rendered screen text for this slice
    val cursorRow: UShort,
    val cursorCol: UShort,
)

sealed class GonomadError : Exception() {
    data class Denied(val capability: String) : GonomadError()
    object NotFound : GonomadError()
    data class RateLimited(val retryAfterMs: UInt) : GonomadError()
    data class Unsupported(val feature: String) : GonomadError()
    data class Transport(val detail: String) : GonomadError()
    data class Protocol(val detail: String) : GonomadError()
    object NotPaired : GonomadError()
}

fun interface StatusListener {
    fun onStatus(status: Status)
}

fun interface TerminalListener {
    fun onFrame(frame: TerminalFrame)
}

interface GonomadClient {

    /** True once this device has completed pairing with some daemon. */
    fun isPaired(): Boolean

    /** The stored daemon, if paired. */
    fun pairedDaemon(): DeviceInfo?

    /**
     * Completes pairing from a scanned QR payload.
     *
     * Runs the IKpsk2 handshake, then returns the six-digit SAS. The UI MUST
     * show it and require the user to confirm it matches the laptop before
     * calling [confirmPairing] — that comparison is the defence against a
     * photographed QR (ARCHITECTURE.md 9.2).
     */
    suspend fun beginPairing(qrPayload: String): String // the SAS, e.g. "418 273"

    /** Commits the pairing after the user confirmed the SAS matched. */
    suspend fun confirmPairing(deviceName: String)

    /** Abandons an in-progress pairing (SAS mismatch, or user cancelled). */
    fun cancelPairing()

    suspend fun connect()

    fun disconnect()

    fun status(): Status

    /** Emits on every connection-state change. Backed by a Rust callback. */
    fun observeStatus(listener: StatusListener)

    // --- filesystem ---

    suspend fun listDir(path: String): List<DirEntry>

    suspend fun readFile(path: String): FileContent

    suspend fun workspaceRoots(): List<String>

    // --- terminal ---

    suspend fun spawnTerminal(cwd: String?): ULong

    suspend fun sendInput(ptyId: ULong, data: String)

    suspend fun resizeTerminal(ptyId: ULong, cols: UShort, rows: UShort)

    suspend fun closeTerminal(ptyId: ULong)

    fun observeTerminal(listener: TerminalListener)

    /** Forgets the daemon and wipes local keys. */
    fun unpair()
}
