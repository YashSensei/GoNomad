package dev.gonomad.app.ffi

import dev.gonomad.ffi.GonomadClientInterface
import dev.gonomad.ffi.Status
import dev.gonomad.ffi.StatusListener
import dev.gonomad.ffi.TerminalFrame
import dev.gonomad.ffi.TerminalListener
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Adapts the core's callback interfaces to Flows, **once**, for the whole process.
 *
 * `observeStatus` and `observeTerminal` each have a single slot in Rust and no
 * way to unregister, so a second registration silently starves the first. This
 * class is the only place in the app that calls either of them; everything else
 * collects [status] or [frames]. That is not a style preference — a
 * `callbackFlow` per call site would work in testing and then break the moment
 * two screens were alive at once.
 *
 * It holds no protocol logic: it stores what the core pushed, plus a little
 * purely-local UI state (recently opened files) the core has no opinion on.
 * Nothing here is persisted — the daemon is the source of truth (§2).
 */
class SessionRepository(val client: GonomadClientInterface) {

    private val _status = MutableStateFlow(client.status())
    val status: StateFlow<Status> = _status.asStateFlow()

    /**
     * Every terminal frame the core pushes, for every PTY.
     *
     * Replay 1 closes a startup race: the listener is registered in this
     * constructor, and [TerminalsRepository] subscribes a moment later, so
     * without a replay buffer a frame that arrived in between would be dropped.
     * Re-delivering one frame is idempotent — a frame is a whole screen.
     */
    private val _frames = MutableSharedFlow<TerminalFrame>(replay = 1, extraBufferCapacity = 64)
    val frames: SharedFlow<TerminalFrame> = _frames.asSharedFlow()

    private val _recentFiles = MutableStateFlow<List<String>>(emptyList())
    val recentFiles: StateFlow<List<String>> = _recentFiles.asStateFlow()

    init {
        // The generated listeners are plain interfaces, not `fun interface`, so
        // a lambda will not convert; these have to be object expressions.
        client.observeStatus(
            object : StatusListener {
                override fun onStatus(status: Status) {
                    _status.value = status
                }
            },
        )
        client.observeTerminal(
            object : TerminalListener {
                override fun onFrame(frame: TerminalFrame) {
                    _frames.tryEmit(frame)
                }
            },
        )
    }

    fun noteFileOpened(path: String) {
        _recentFiles.update { current ->
            (listOf(path) + current.filterNot { it == path }).take(MAX_RECENTS)
        }
    }

    fun clearRecents() {
        _recentFiles.value = emptyList()
    }

    private companion object {
        const val MAX_RECENTS = 6
    }
}
