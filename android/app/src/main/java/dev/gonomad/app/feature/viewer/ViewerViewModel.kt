package dev.gonomad.app.feature.viewer

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.gonomad.ffi.FileContent
import dev.gonomad.app.ffi.SessionRepository
import dev.gonomad.app.ui.common.ErrorPresentation
import dev.gonomad.app.ui.common.toPresentation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class ViewerUiState(
    val path: String,
    val loading: Boolean = true,
    val content: FileContent? = null,
    val lines: List<String> = emptyList(),
    val error: ErrorPresentation? = null,
) {
    val fileName: String get() = path.substringAfterLast('/')
    val directory: String get() = path.substringBeforeLast('/', "")
}

class ViewerViewModel(
    private val session: SessionRepository,
    private val path: String,
) : ViewModel() {

    private val _state = MutableStateFlow(ViewerUiState(path = path))
    val state: StateFlow<ViewerUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    private fun load() {
        _state.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            runCatching { session.client.readFile(path) }
                .onSuccess { content ->
                    // Splitting a multi-megabyte file is real work; keeping it
                    // off the main thread is the difference between a smooth
                    // open and a dropped frame budget.
                    val lines = withContext(Dispatchers.Default) { content.text.lines() }
                    _state.update {
                        it.copy(loading = false, content = content, lines = lines)
                    }
                }
                .onFailure { e ->
                    _state.update { it.copy(loading = false, error = e.toPresentation()) }
                }
        }
    }
}
