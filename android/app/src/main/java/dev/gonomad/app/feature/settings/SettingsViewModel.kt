package dev.gonomad.app.feature.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.gonomad.app.ffi.ClientProvider
import dev.gonomad.app.ffi.SessionRepository
import dev.gonomad.app.ffi.TerminalsRepository
import dev.gonomad.ffi.DeviceInfo
import dev.gonomad.ffi.Status
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class SettingsUiState(
    val status: Status,
    val daemon: DeviceInfo?,
    val confirmingUnpair: Boolean = false,
    val unpaired: Boolean = false,
)

class SettingsViewModel(
    private val session: SessionRepository,
    private val terminals: TerminalsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(
        SettingsUiState(
            status = session.client.status(),
            daemon = session.client.pairedDaemon(),
        ),
    )
    val state: StateFlow<SettingsUiState> = _state.asStateFlow()

    /** True when the app is talking to [dev.gonomad.app.ffi.fake.FakeGonomadClient]. */
    val usingFakeCore: Boolean = ClientProvider.USE_FAKE

    init {
        viewModelScope.launch {
            session.status.collect { status -> _state.update { it.copy(status = status) } }
        }
    }

    fun askToUnpair() {
        _state.update { it.copy(confirmingUnpair = true) }
    }

    fun dismissUnpair() {
        _state.update { it.copy(confirmingUnpair = false) }
    }

    /**
     * Destructive and irreversible: there is no password reset because there is
     * no password, so this is behind a confirmation (ARCHITECTURE.md 23.1,
     * principle 5).
     */
    fun confirmUnpair() {
        session.client.unpair()
        session.clearRecents()
        // The tabs are a view of a machine this phone can no longer reach, so
        // they are forgotten locally. Nothing is killed: the PTYs belong to the
        // machine, and it decides what to do with them.
        terminals.forgetAll()
        _state.update { it.copy(confirmingUnpair = false, unpaired = true, daemon = null) }
    }
}
