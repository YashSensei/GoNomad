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

/** A newly spawned terminal and its first screen. */
data class TerminalHandle(
    val ptyId: ULong,
    val initial: TerminalFrame,
)

sealed class GonomadError : Exception() {
    data class Denied(val capability: String) : GonomadError()
    object NotFound : GonomadError()
    data class RateLimited(val retryAfterMs: UInt) : GonomadError()
    data class Unsupported(val feature: String) : GonomadError()
    data class Transport(val detail: String) : GonomadError()
    data class Protocol(val detail: String) : GonomadError()
    object PairingRejected : GonomadError()
    object NotPaired : GonomadError()
}
```

`PairingRejected` and `Transport` are both reachable from a failed pairing and must
not be presented alike. `PairingRejected` means the machine answered and turned the
code down — rescanning is the fix. `Transport` means nothing answered, so the code
was never even checked; telling the user to re-read their six digits is actively
misleading. The split exists because the two were conflated once and it cost real
debugging time.

## The client object

> [!IMPORTANT]
> **The Kotlin side must code against an `interface`, not this class.**
> UniFFI generates a concrete class, and a Kotlin interface cannot declare a
> `companion object`. So `create` lives on a separate `ClientProvider`, and the
> interface carries instance methods only; the generated class satisfies it
> structurally. That indirection is also what lets a fake be substituted for
> previews and for building the app before the Rust core exists.

```kotlin
class GonomadClient {
    companion object {
        /** Loads a persisted identity, or creates one on first run. */
        fun create(stateDir: String): GonomadClient
    }

    /**
     * True once this device has completed pairing with some daemon.
     *
     * Synchronous, so the implementation must answer from memory. Reading the
     * Keystore here would put a disk-and-keymaster round trip on whatever thread
     * calls it; load once at construction and cache.
     */
    fun isPaired(): Boolean

    /** The stored daemon, if paired. Synchronous, as [isPaired]. */
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

    /**
     * Commits the pairing after the user confirmed the SAS matched.
     *
     * `deviceName` is **this phone's** name, as it will appear in the daemon's
     * device list and audit log — not the daemon's name. The daemon's own name
     * comes back from [pairedDaemon].
     *
     * Implementation constraint (`ARCHITECTURE.md` §19 R24): with `IKpsk2` the
     * daemon completes its side of the handshake even when the pairing code was
     * wrong, so this call MUST perform an authenticated application-level
     * exchange over the control stream and only report success if that
     * round-trips. Treating handshake completion as success would register a
     * device that guessed nothing.
     */
    suspend fun confirmPairing(deviceName: String)

    /** Abandons an in-progress pairing (SAS mismatch, or user cancelled). */
    fun cancelPairing()

    suspend fun connect()
    fun disconnect()
    fun status(): Status

    /**
     * Emits on every connection-state change. Backed by a Rust callback.
     *
     * **Single registration.** The Rust side holds exactly one listener, so
     * calling this twice replaces the first — a second call site would silently
     * stop the first from receiving anything. Register once in a process-wide
     * repository and fan out to consumers with a `SharedFlow`. Do not wrap this
     * in a per-call-site `callbackFlow`.
     */
    fun observeStatus(listener: StatusListener)

    // --- filesystem ---
    suspend fun listDir(path: String): List<DirEntry>
    suspend fun readFile(path: String): FileContent
    suspend fun workspaceRoots(): List<String>

    // --- terminal ---
    /**
     * Spawns a terminal and returns its first frame along with its id.
     *
     * Returns the frame rather than only the id so the UI can distinguish
     * "spawned, no output yet" from "spawned, first frame lost" — with an id
     * alone those two are indistinguishable and the screen stays blank forever.
     */
    suspend fun spawnTerminal(cwd: String?): TerminalHandle

    suspend fun sendInput(ptyId: ULong, data: String)
    suspend fun resizeTerminal(ptyId: ULong, cols: UShort, rows: UShort)
    suspend fun closeTerminal(ptyId: ULong)

    /** Single registration, exactly as [observeStatus]. */
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
