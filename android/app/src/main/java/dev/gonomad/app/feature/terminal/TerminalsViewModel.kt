package dev.gonomad.app.feature.terminal

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.gonomad.app.ffi.TerminalTab
import dev.gonomad.app.ffi.TerminalsRepository
import dev.gonomad.app.ui.common.ErrorPresentation
import dev.gonomad.app.ui.common.toPresentation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class TerminalsUiState(
    val tabs: List<TerminalTab> = emptyList(),
    val activeId: ULong? = null,
    val spawning: Boolean = false,
    val draft: String = "",
    val sticky: StickyModifier = StickyModifier.None,
    val switcherOpen: Boolean = false,
    val error: ErrorPresentation? = null,
) {
    val active: TerminalTab? get() = tabs.firstOrNull { it.ptyId == activeId }

    val unreadCount: Int get() = tabs.count { it.hasUnread }
}

/**
 * Drives the terminal screen and its tabs.
 *
 * The terminals themselves live in [TerminalsRepository], above this class, so
 * nothing here can end one: this `ViewModel` is cleared every time the user
 * navigates away, and if it owned the PTYs then leaving the screen would kill a
 * running build. What it does own is the *screen* — draft text, the armed sticky
 * modifier, whether the switcher is up — none of which the daemon cares about.
 *
 * Input model: the text field is a **composer**. What you type stays local until
 * you send it, because a phone keyboard with autocorrect and IME composition
 * cannot sanely stream one byte per keystroke. Two things bypass it: accessory
 * keys with no textual form (Esc, Tab, the arrows), and any keystroke while a
 * modifier is armed — which is what makes `Ctrl` then `c` send 0x03 rather than
 * the letter c.
 */
class TerminalsViewModel(private val terminals: TerminalsRepository) : ViewModel() {

    /** Purely-local screen state; the tabs come from the repository. */
    private data class Local(
        val spawning: Boolean = false,
        val draft: String = "",
        val sticky: StickyModifier = StickyModifier.None,
        val switcherOpen: Boolean = false,
        val error: ErrorPresentation? = null,
    )

    private val _local = MutableStateFlow(Local())

    /** The cwd this screen was opened for, so "+" and retry know where to spawn. */
    private var openedFor: String? = null

    val state: StateFlow<TerminalsUiState> =
        combine(terminals.tabs, terminals.activeId, _local) { tabs, activeId, local ->
            TerminalsUiState(
                tabs = tabs,
                activeId = activeId,
                spawning = local.spawning,
                draft = local.draft,
                sticky = local.sticky,
                switcherOpen = local.switcherOpen,
                error = local.error,
            )
        }.stateIn(viewModelScope, SharingStarted.Eagerly, TerminalsUiState())

    // --- tabs ----------------------------------------------------------------

    /**
     * Called on arriving at the screen.
     *
     * Idempotent by way of [TerminalsRepository.openOrSelect]: coming back from
     * the file viewer selects the terminal that is already open on this path
     * rather than spawning a second shell in it.
     */
    fun onScreenEntered(cwd: String) {
        openedFor = cwd
        spawn { terminals.openOrSelect(cwd) }
    }

    /** An explicit new tab, in the same directory as the one you are looking at. */
    fun newTerminal() {
        val cwd = state.value.active?.cwd ?: openedFor ?: return
        _local.update { it.copy(switcherOpen = false) }
        spawn { terminals.open(cwd) }
    }

    fun retry() {
        val cwd = openedFor ?: return
        spawn { terminals.openOrSelect(cwd) }
    }

    /** Switching tabs sends nothing to the machine and ends nothing. */
    fun selectTab(ptyId: ULong) {
        terminals.select(ptyId)
        _local.update { it.copy(switcherOpen = false, draft = "", sticky = StickyModifier.None) }
    }

    /**
     * The only way a terminal ends from this app.
     *
     * Offered from the switcher only, never from a tab pill: a mis-tap on a row
     * of pills must not be able to kill a running process (§13.5).
     */
    fun closeTab(ptyId: ULong) {
        viewModelScope.launch {
            runCatching { terminals.close(ptyId) }
                .onFailure { e -> _local.update { it.copy(error = e.toPresentation()) } }
        }
    }

    fun openSwitcher() {
        _local.update { it.copy(switcherOpen = true) }
    }

    fun closeSwitcher() {
        _local.update { it.copy(switcherOpen = false) }
    }

    fun dismissError() {
        _local.update { it.copy(error = null) }
    }

    // --- input ---------------------------------------------------------------

    fun onDraftChanged(text: String) {
        val local = _local.value

        // A modifier is armed, so the next keystroke belongs to the PTY and not
        // to the composer. This is the path Ctrl-C takes: `c` never reaches the
        // draft, 0x03 goes straight to the shell, and the modifier disarms.
        if (local.sticky != StickyModifier.None) {
            val typed = firstNewChar(local.draft, text)
            if (typed != null) {
                write(AccessoryKeys.applyModifier(local.sticky, typed.toString()))
                _local.update { it.copy(sticky = StickyModifier.None) }
                return
            }
        }

        // Some IMEs deliver their own Enter as a newline in the value rather than
        // as an ImeAction; treat it as a send instead of letting it into the draft.
        if (text.contains('\n')) {
            _local.update { it.copy(draft = text.substringBefore('\n')) }
            send()
            return
        }
        _local.update { it.copy(draft = text) }
    }

    fun send() {
        val draft = _local.value.draft
        _local.update { it.copy(draft = "") }
        // Carriage return, not newline: that is what Enter transmits, and ConPTY
        // on the Windows host will not submit a line for a bare LF.
        write(draft + "\r")
    }

    fun onToggleModifier(which: StickyModifier) {
        _local.update {
            it.copy(sticky = if (it.sticky == which) StickyModifier.None else which)
        }
    }

    /**
     * An accessory key. With a modifier armed everything goes to the PTY; without
     * one, a plain printable character is inserted into the composer so `|`, `~`,
     * `$` and friends behave like the keyboard keys they replace.
     */
    fun onAccessoryKey(key: AccessoryKey) {
        val raw = key.send ?: return
        val sticky = _local.value.sticky

        if (sticky == StickyModifier.None && raw.length == 1 && raw[0].code >= 0x20) {
            _local.update { it.copy(draft = it.draft + raw) }
            return
        }

        write(AccessoryKeys.applyModifier(sticky, raw))
        // Sticky means one keypress, then off. Leaving it armed is how people end
        // up sending Ctrl+L when they meant l.
        _local.update { it.copy(sticky = StickyModifier.None) }
    }

    /**
     * The measured geometry of the output surface.
     *
     * The daemon spawns every PTY at 80x24, so until this lands, `htop` and
     * friends draw for a screen that does not exist. Failures are deliberately
     * not surfaced: a resize that misses is a cosmetic problem, and blanking the
     * terminal with an error banner over one would not be.
     */
    fun onSurfaceMeasured(cols: Int, rows: Int) {
        val id = state.value.activeId ?: return
        viewModelScope.launch {
            runCatching {
                terminals.resize(
                    id,
                    cols.coerceIn(MIN_COLS, MAX_COLS).toUShort(),
                    rows.coerceIn(MIN_ROWS, MAX_ROWS).toUShort(),
                )
            }
        }
    }

    // --- internals -----------------------------------------------------------

    private fun write(data: String) {
        val id = state.value.activeId ?: return
        viewModelScope.launch {
            runCatching { terminals.sendInput(id, data) }
                .onFailure { e -> _local.update { it.copy(error = e.toPresentation()) } }
        }
    }

    private fun spawn(block: suspend () -> Unit) {
        if (_local.value.spawning) return
        _local.update { it.copy(spawning = true, error = null) }
        viewModelScope.launch {
            runCatching { block() }
                .onFailure { e -> _local.update { it.copy(error = e.toPresentation()) } }
            _local.update { it.copy(spawning = false) }
        }
    }

    /**
     * The character just typed, found by common prefix rather than by taking the
     * last one — the caret is not always at the end of the field.
     */
    private fun firstNewChar(old: String, new: String): Char? {
        if (new.length <= old.length) return null
        var i = 0
        while (i < old.length && old[i] == new[i]) i++
        return new.getOrNull(i)
    }

    private companion object {
        const val MIN_COLS = 20
        const val MAX_COLS = 500
        const val MIN_ROWS = 4
        const val MAX_ROWS = 200
    }
}
