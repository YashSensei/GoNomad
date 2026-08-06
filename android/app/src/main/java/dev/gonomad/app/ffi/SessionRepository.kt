package dev.gonomad.app.ffi

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Adapts the core's callback interfaces to Flows, once, for the whole process.
 *
 * The contract exposes `observeStatus(listener)` and `observeTerminal(listener)`
 * with a single slot and no way to unregister, so wrapping each call site in
 * its own `callbackFlow` would have later collectors silently displace earlier
 * ones. Registering exactly once here and fanning out through Flow is the only
 * safe reading of that API.
 *
 * This holds no protocol logic — it stores what the core told us, plus a little
 * purely-local UI state (recently opened files) that the core has no opinion on.
 */
class SessionRepository(val client: GonomadClient) {

    private val _status = MutableStateFlow(client.status())
    val status: StateFlow<Status> = _status.asStateFlow()

    /** Replay 1 so a terminal screen re-entered from the back stack repaints. */
    private val _frames = MutableSharedFlow<TerminalFrame>(replay = 1, extraBufferCapacity = 64)
    val frames: SharedFlow<TerminalFrame> = _frames.asSharedFlow()

    private val _recentFiles = MutableStateFlow<List<String>>(emptyList())
    val recentFiles: StateFlow<List<String>> = _recentFiles.asStateFlow()

    init {
        client.observeStatus { _status.value = it }
        client.observeTerminal { _frames.tryEmit(it) }
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
