package dev.gonomad.app.feature.terminal

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.gonomad.app.ffi.SessionRepository
import dev.gonomad.app.ui.common.ErrorPresentation
import dev.gonomad.app.ui.common.toPresentation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class TerminalUiState(
    val cwd: String,
    val ptyId: ULong? = null,
    val starting: Boolean = true,
    val screen: String = "",
    val draft: String = "",
    val sticky: StickyModifier = StickyModifier.None,
    val error: ErrorPresentation? = null,
)

/**
 * Drives one PTY.
 *
 * Input model: the text field is a *composer*. What you type stays local until
 * you send it, because a phone keyboard with autocorrect and IME composition
 * cannot sanely stream one byte per keystroke. Keys that have no textual form —
 * Esc, Tab, the arrows, and anything under a sticky Ctrl or Alt — go straight
 * to the PTY, since those are exactly the keys you cannot type into a field.
 */
class TerminalViewModel(
    private val session: SessionRepository,
    private val cwd: String,
) : ViewModel() {

    private val _state = MutableStateFlow(TerminalUiState(cwd = cwd))
    val state: StateFlow<TerminalUiState> = _state.asStateFlow()

    init {
        spawn()
    }

    private fun spawn() {
        _state.update { it.copy(starting = true, error = null) }
        viewModelScope.launch {
            runCatching { session.client.spawnTerminal(cwd) }
                .onSuccess { id ->
                    _state.update { it.copy(ptyId = id, starting = false) }
                    observe(id)
                }
                .onFailure { e ->
                    _state.update { it.copy(starting = false, error = e.toPresentation()) }
                }
        }
    }

    private fun observe(id: ULong) {
        viewModelScope.launch {
            session.frames
                .filter { it.ptyId == id }
                .collect { frame -> _state.update { it.copy(screen = frame.screen) } }
        }
    }

    fun retry() = spawn()

    fun onDraftChanged(text: String) {
        // A newline can arrive from the soft keyboard's own Enter key on some
        // IMEs; treat it as a send rather than letting it into the draft.
        if (text.contains('\n')) {
            _state.update { it.copy(draft = text.substringBefore('\n')) }
            send()
            return
        }
        _state.update { it.copy(draft = text) }
    }

    fun send() {
        val draft = _state.value.draft
        _state.update { it.copy(draft = "") }
        write(draft + "\n")
    }

    fun onToggleModifier(which: StickyModifier) {
        _state.update {
            it.copy(sticky = if (it.sticky == which) StickyModifier.None else which)
        }
    }

    /**
     * An accessory key. With a modifier armed, everything goes to the PTY;
     * without one, a plain printable character is inserted into the composer so
     * `|`, `~`, `$` and friends behave like the keyboard keys they replace.
     */
    fun onAccessoryKey(key: AccessoryKey) {
        val raw = key.send ?: return
        val sticky = _state.value.sticky

        if (sticky == StickyModifier.None && raw.length == 1 && raw[0].code >= 0x20) {
            _state.update { it.copy(draft = it.draft + raw) }
            return
        }

        write(AccessoryKeys.applyModifier(sticky, raw))
        // Sticky means one keypress, then off. Leaving it armed is how users
        // end up sending Ctrl+L when they meant l.
        _state.update { it.copy(sticky = StickyModifier.None) }
    }

    fun onResize(cols: Int, rows: Int) {
        val id = _state.value.ptyId ?: return
        viewModelScope.launch {
            runCatching {
                session.client.resizeTerminal(
                    id,
                    cols.coerceIn(20, 500).toUShort(),
                    rows.coerceIn(4, 200).toUShort(),
                )
            }
        }
    }

    private fun write(data: String) {
        val id = _state.value.ptyId ?: return
        viewModelScope.launch {
            runCatching { session.client.sendInput(id, data) }
                .onFailure { e -> _state.update { it.copy(error = e.toPresentation()) } }
        }
    }

    override fun onCleared() {
        super.onCleared()
        // The PTY deliberately outlives this ViewModel: leaving a screen must
        // not kill a running test suite (ARCHITECTURE.md 2). Closing it is an
        // explicit user action, not a lifecycle side effect.
    }
}
