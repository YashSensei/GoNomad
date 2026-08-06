# FFI contract — the Rust ↔ Kotlin boundary

The single source of truth for the boundary between `gonomad-ffi` (Rust, via
UniFFI) and the Android app (Kotlin). Both sides are written against this
document, so it must be updated *before* either side changes.

> [!NOTE]
> This describes the **M1.5 vertical slice**: pair over LAN, browse files, read a
> file, run a terminal. It is not the full API surface from `ARCHITECTURE.md`
> §11, which lands milestone by milestone.

## Design rules

1. **Kotlin holds no protocol logic.** Every state machine, retry policy, and
   crypto operation lives in Rust (`ARCHITECTURE.md` §6.2). If a Kotlin file
   contains a conditional about protocol state, it belongs in Rust.
2. **The boundary is coarse.** Few methods, rich types. Each FFI crossing has
   overhead, and a chatty interface would put it on the hot path.
3. **Errors are a closed enum**, mirroring `ProtoError`, so Compose can render a
   correct action for each (`ARCHITECTURE.md` §11.2).
4. **Nothing blocks the main thread.** Every call is `suspend` on the Kotlin
   side; UniFFI async maps to Rust async.

## Types

```kotlin
enum class ConnState { DISCONNECTED, CONNECTING, CONNECTED, UNPAIRED, REVOKED }

data class DeviceInfo(
    val deviceId: String,      // hex, short form for display
    val name: String,
    val pairedAt: Long,        // unix ms
    val lastSeen: Long?,
)

data class Status(
    val state: ConnState,
    val daemonName: String?,   // e.g. "DESKTOP-ABC"
    val rttMs: UInt?,
    val transport: String?,    // "LAN" for this slice
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
    val text: String,          // UTF-8; binary files are refused
    val contentHash: String,   // CAS baseline for a future write
    val truncated: Boolean,    // true if the file exceeded the read cap
)

data class TerminalFrame(
    val ptyId: ULong,
    val screen: String,        // rendered screen text for this slice
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
```

## The client object

```kotlin
class GonomadClient {
    companion object {
        /** Loads a persisted identity, or creates one on first run. */
        fun create(stateDir: String): GonomadClient
    }

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
    suspend fun beginPairing(qrPayload: String): String   // the SAS, e.g. "418 273"

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

interface StatusListener { fun onStatus(status: Status) }
interface TerminalListener { fun onFrame(frame: TerminalFrame) }
```

## Wire methods this maps to

| Kotlin call | Protocol method |
|---|---|
| `listDir` | `fs.list` |
| `readFile` | `fs.read` |
| `workspaceRoots` | from `HelloOk.workspace_roots` |
| `spawnTerminal` | `pty.spawn` |
| `sendInput` | `pty.input` |
| `resizeTerminal` | `pty.resize` |
| `closeTerminal` | `pty.kill` |
| terminal frames | `pty.output` on the PTY stream |

## Not in this slice

Writing files, search, git, AI agents, notifications, multi-device, presence
signatures, and the cell-diff terminal renderer. `TerminalFrame.screen` carries a
rendered screen as text; the Compose `Canvas` glyph-atlas renderer and cell diffs
(`ARCHITECTURE.md` §13) arrive with M2.
