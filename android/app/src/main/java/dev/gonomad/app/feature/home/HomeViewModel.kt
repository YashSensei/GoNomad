package dev.gonomad.app.feature.home

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.gonomad.ffi.ConnState
import dev.gonomad.ffi.DeviceInfo
import dev.gonomad.app.ffi.SessionRepository
import dev.gonomad.ffi.Status
import dev.gonomad.app.ui.common.ErrorPresentation
import dev.gonomad.app.ui.common.toPresentation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class WorkspaceCard(
    val root: String,
    val name: String,
) {
    /** Stable across recompositions and reorderings; used as the LazyColumn key. */
    val id: String get() = root
}

data class HomeUiState(
    val status: Status,
    val daemon: DeviceInfo?,
    val workspaces: List<WorkspaceCard> = emptyList(),
    val recentFiles: List<String> = emptyList(),
    val loadingWorkspaces: Boolean = false,
    val error: ErrorPresentation? = null,
) {
    val connected: Boolean get() = status.state == ConnState.CONNECTED
    val busy: Boolean get() = status.state == ConnState.CONNECTING
}

class HomeViewModel(private val session: SessionRepository) : ViewModel() {

    private val _state = MutableStateFlow(
        HomeUiState(
            status = session.client.status(),
            daemon = session.client.pairedDaemon(),
        ),
    )
    val state: StateFlow<HomeUiState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            session.status.collect { status ->
                _state.update { it.copy(status = status, daemon = session.client.pairedDaemon()) }
                // The daemon is the authority on what roots exist, so the list
                // is (re)fetched whenever a session comes up rather than cached.
                if (status.state == ConnState.CONNECTED && _state.value.workspaces.isEmpty()) {
                    loadWorkspaces()
                }
            }
        }
        viewModelScope.launch {
            session.recentFiles.collect { recents ->
                _state.update { it.copy(recentFiles = recents) }
            }
        }
        connect()
    }

    fun connect() {
        if (_state.value.busy || _state.value.connected) return
        viewModelScope.launch {
            _state.update { it.copy(error = null) }
            runCatching { session.client.connect() }
                .onFailure { e -> _state.update { it.copy(error = e.toPresentation()) } }
        }
    }

    fun disconnect() {
        session.client.disconnect()
        _state.update { it.copy(workspaces = emptyList()) }
    }

    fun retry() {
        _state.update { it.copy(error = null) }
        if (_state.value.connected) loadWorkspaces() else connect()
    }

    private fun loadWorkspaces() {
        viewModelScope.launch {
            _state.update { it.copy(loadingWorkspaces = true, error = null) }
            runCatching { session.client.workspaceRoots() }
                .onSuccess { roots ->
                    _state.update { s ->
                        s.copy(
                            loadingWorkspaces = false,
                            workspaces = roots.map { WorkspaceCard(it, it.substringAfterLast('/')) },
                        )
                    }
                }
                .onFailure { e ->
                    _state.update { it.copy(loadingWorkspaces = false, error = e.toPresentation()) }
                }
        }
    }
}
