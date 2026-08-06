package dev.gonomad.app.ffi

import dev.gonomad.ffi.GonomadClientInterface
import dev.gonomad.ffi.GonomadException
import dev.gonomad.ffi.TerminalFrame
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.updateAndGet
import kotlinx.coroutines.launch

/** Whether a terminal is still alive on the machine. */
enum class TerminalRunState { RUNNING, EXITED }

/**
 * One open terminal, as the tab row and the switcher see it.
 *
 * This is a *view* of daemon state, never a cache of it: the screen is whatever
 * frame arrived last, and nothing here is written to disk. The daemon owns the
 * PTY, its scrollback, and its lifetime (§2).
 */
data class TerminalTab(
    val ptyId: ULong,
    val cwd: String,
    val screen: String,
    val cursorRow: UShort,
    val cursorCol: UShort,
    val runState: TerminalRunState,
    /** Output arrived while this tab was not the visible one. */
    val hasUnread: Boolean,
    /** The last geometry sent to the daemon, so a resize is not re-sent. */
    val cols: UShort,
    val rows: UShort,
) {
    /** Last path segment, which is what identifies a terminal in practice. */
    val title: String
        get() = cwd.trimEnd('/').substringAfterLast('/').ifBlank { "pty $ptyId" }

    val running: Boolean get() = runState == TerminalRunState.RUNNING
}

/**
 * The set of open terminals, process-scoped.
 *
 * ### Why this exists
 *
 * The daemon owns terminals (§2), so a backgrounded one keeps running — a test
 * suite does not die because you went to look at a file. Making that true on the
 * phone needs exactly one property: **no lifecycle event may call
 * `closeTerminal`.** So the set of open PTYs lives here, above every `ViewModel`
 * and above the navigation graph, and [close] is the only caller of
 * `closeTerminal` in the whole app. Switching tabs, leaving the screen, and
 * process-level configuration changes all mutate nothing.
 *
 * Frames arrive from [SessionRepository.frames], which holds the one permitted
 * `observeTerminal` registration. They are already produced by a 150 ms poll
 * inside the Rust client, so there is deliberately no poller here — a second one
 * would double the request rate for no extra information.
 *
 * ### Exit detection is weaker than it looks
 *
 * `TerminalFrame` carries no exit flag (the Rust `ScreenFrame.exited` is dropped
 * at the FFI boundary) and the poller simply stops publishing once a shell has
 * gone. So a terminal is marked [TerminalRunState.EXITED] when the daemon answers
 * `NotFound` for it — the truth, just discovered late. Under-reporting an exit is
 * better than guessing one from screen text.
 */
class TerminalsRepository(
    private val client: GonomadClientInterface,
    frames: SharedFlow<TerminalFrame>,
    scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
) {

    private val _tabs = MutableStateFlow<List<TerminalTab>>(emptyList())
    val tabs: StateFlow<List<TerminalTab>> = _tabs.asStateFlow()

    private val _activeId = MutableStateFlow<ULong?>(null)
    val activeId: StateFlow<ULong?> = _activeId.asStateFlow()

    init {
        scope.launch {
            frames.collect(::onFrame)
        }
    }

    // --- lifecycle -----------------------------------------------------------

    /**
     * Selects the terminal already open on [cwd], or spawns one there.
     *
     * Idempotent, because it is driven by arriving at the terminal screen: a
     * navigation that spawned a PTY every time would leave a trail of shells
     * behind an ordinary back-and-forward.
     */
    suspend fun openOrSelect(cwd: String): ULong {
        val existing = _tabs.value.firstOrNull { it.cwd == cwd && it.running }
        if (existing != null) {
            select(existing.ptyId)
            return existing.ptyId
        }
        return open(cwd)
    }

    /**
     * Spawns a terminal and shows it.
     *
     * `spawnTerminal` returns the first frame along with the id, so the tab is
     * created with a screen already in it. Waiting for the first poll instead
     * would leave the surface blank for up to 150 ms and, worse, make "spawned
     * but silent" indistinguishable from "spawned and the first frame was lost".
     */
    suspend fun open(cwd: String): ULong {
        val handle = client.spawnTerminal(cwd)
        val tab = TerminalTab(
            ptyId = handle.ptyId,
            cwd = cwd,
            screen = handle.initial.screen,
            cursorRow = handle.initial.cursorRow,
            cursorCol = handle.initial.cursorCol,
            runState = TerminalRunState.RUNNING,
            hasUnread = false,
            cols = UNMEASURED,
            rows = UNMEASURED,
        )
        _tabs.update { current ->
            // A recycled id would otherwise appear twice; the newer one wins.
            current.filterNot { it.ptyId == tab.ptyId } + tab
        }
        _activeId.value = tab.ptyId
        return tab.ptyId
    }

    /** Shows a tab. Kills nothing — the other terminals keep running. */
    fun select(ptyId: ULong) {
        _activeId.value = ptyId
        _tabs.update { current ->
            current.map { if (it.ptyId == ptyId) it.copy(hasUnread = false) else it }
        }
    }

    /**
     * Terminates a terminal, and is the only thing in the app that does.
     *
     * `NotFound` counts as success: the shell had already gone, and the tab must
     * still disappear. Anything else is rethrown for the caller to render.
     */
    suspend fun close(ptyId: ULong) {
        val outcome = runCatching { client.closeTerminal(ptyId) }
        drop(ptyId)
        val error = outcome.exceptionOrNull()
        if (error != null && error !is GonomadException.NotFound) throw error
    }

    /** Forgets every tab locally, for unpairing. Sends nothing to the machine. */
    fun forgetAll() {
        _tabs.value = emptyList()
        _activeId.value = null
    }

    // --- input ---------------------------------------------------------------

    suspend fun sendInput(ptyId: ULong, data: String) {
        if (data.isEmpty()) return
        onLiveTerminal(ptyId) { client.sendInput(ptyId, data) }
    }

    /**
     * Tells the daemon the real geometry.
     *
     * The Rust client spawns at 80x24 until told otherwise, which makes every
     * full-screen program wrap in the wrong place on a phone. Sending only on a
     * genuine change keeps this off the 150 ms path.
     */
    suspend fun resize(ptyId: ULong, cols: UShort, rows: UShort) {
        val tab = _tabs.value.firstOrNull { it.ptyId == ptyId } ?: return
        if (tab.cols == cols && tab.rows == rows) return
        onLiveTerminal(ptyId) { client.resizeTerminal(ptyId, cols, rows) }
        _tabs.update { current ->
            current.map { if (it.ptyId == ptyId) it.copy(cols = cols, rows = rows) else it }
        }
    }

    // --- internals -----------------------------------------------------------

    private fun onFrame(frame: TerminalFrame) {
        _tabs.update { current ->
            current.map { tab ->
                if (tab.ptyId != frame.ptyId) {
                    tab
                } else {
                    tab.copy(
                        screen = frame.screen,
                        cursorRow = frame.cursorRow,
                        cursorCol = frame.cursorCol,
                        // The Rust poller publishes only on change, so any frame
                        // for a tab you are not looking at is unread output.
                        hasUnread = tab.hasUnread || tab.ptyId != _activeId.value,
                    )
                }
            }
        }
    }

    /**
     * Runs an operation on a terminal, marking it exited if the daemon has
     * forgotten it. Every failure still reaches the caller.
     */
    private suspend fun onLiveTerminal(ptyId: ULong, block: suspend () -> Unit) {
        val error = runCatching { block() }.exceptionOrNull() ?: return
        if (error is GonomadException.NotFound) markExited(ptyId)
        throw error
    }

    private fun markExited(ptyId: ULong) {
        _tabs.update { current ->
            current.map {
                if (it.ptyId == ptyId) it.copy(runState = TerminalRunState.EXITED) else it
            }
        }
    }

    private fun drop(ptyId: ULong) {
        val remaining = _tabs.updateAndGet { current -> current.filterNot { it.ptyId == ptyId } }
        if (_activeId.value == ptyId) {
            _activeId.value = remaining.lastOrNull()?.ptyId
        }
    }

    private companion object {
        /**
         * The geometry no measurement can produce, so the first real one is
         * always sent even if the surface happens to be exactly 80x24.
         */
        val UNMEASURED: UShort = 0u
    }
}
