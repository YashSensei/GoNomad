package dev.gonomad.app.feature.files

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.gonomad.app.ffi.DirEntry
import dev.gonomad.app.ffi.EntryKind
import dev.gonomad.app.ffi.SessionRepository
import dev.gonomad.app.ui.common.ErrorPresentation
import dev.gonomad.app.ui.common.toPresentation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** One visible row of the flattened tree. */
data class FileNode(
    val path: String,
    val entry: DirEntry,
    val depth: Int,
    val expanded: Boolean,
    val loadingChildren: Boolean,
)

data class FilesUiState(
    val root: String,
    val loading: Boolean = true,
    val refreshing: Boolean = false,
    val nodes: List<FileNode> = emptyList(),
    val error: ErrorPresentation? = null,
    val showHidden: Boolean = false,
    val showIgnored: Boolean = false,
) {
    val isEmpty: Boolean get() = !loading && error == null && nodes.isEmpty()
}

/**
 * The tree is flattened in the ViewModel, not in the composable: a `LazyColumn`
 * wants a flat list with stable keys, and computing that during composition
 * would re-run on every scroll.
 *
 * Children are fetched lazily on expand and cached, matching the daemon's own
 * lazy `fs.list` (ARCHITECTURE.md 12.5 — a root can hold millions of files).
 */
class FilesViewModel(
    private val session: SessionRepository,
    private val root: String,
) : ViewModel() {

    private val children = mutableMapOf<String, List<DirEntry>>()
    private val expanded = mutableSetOf<String>()
    private val loadingPaths = mutableSetOf<String>()

    private val _state = MutableStateFlow(FilesUiState(root = root))
    val state: StateFlow<FilesUiState> = _state.asStateFlow()

    init {
        load(initial = true)
    }

    fun refresh() {
        _state.update { it.copy(refreshing = true) }
        children.clear()
        load(initial = false)
    }

    fun retry() = load(initial = true)

    fun toggleHidden() {
        _state.update { it.copy(showHidden = !it.showHidden) }
        rebuild()
    }

    fun toggleIgnored() {
        _state.update { it.copy(showIgnored = !it.showIgnored) }
        rebuild()
    }

    fun onNodeClicked(node: FileNode, onOpenFile: (String) -> Unit) {
        when (node.entry.kind) {
            EntryKind.DIRECTORY -> toggle(node.path)
            // A symlink is followed like the thing it points at; the daemon has
            // already resolved and re-validated it against the workspace root.
            EntryKind.SYMLINK -> toggle(node.path)
            EntryKind.FILE -> {
                session.noteFileOpened(node.path)
                onOpenFile(node.path)
            }
        }
    }

    private fun toggle(path: String) {
        if (path in expanded) {
            expanded -= path
            rebuild()
            return
        }
        expanded += path
        if (children.containsKey(path)) {
            rebuild()
        } else {
            fetch(path)
        }
    }

    private fun load(initial: Boolean) {
        _state.update { it.copy(loading = initial, error = null) }
        viewModelScope.launch {
            runCatching { session.client.listDir(root) }
                .onSuccess { entries ->
                    children[root] = entries
                    // Re-expanding a stale directory after a refresh would show
                    // rows from a listing we just discarded, so drop them.
                    expanded.retainAll { children.containsKey(it) }
                    _state.update { it.copy(loading = false, refreshing = false) }
                    rebuild()
                }
                .onFailure { e ->
                    _state.update {
                        it.copy(loading = false, refreshing = false, error = e.toPresentation())
                    }
                }
        }
    }

    private fun fetch(path: String) {
        loadingPaths += path
        rebuild()
        viewModelScope.launch {
            runCatching { session.client.listDir(path) }
                .onSuccess { entries ->
                    children[path] = entries
                    loadingPaths -= path
                    rebuild()
                }
                .onFailure { e ->
                    loadingPaths -= path
                    expanded -= path
                    _state.update { it.copy(error = e.toPresentation()) }
                    rebuild()
                }
        }
    }

    private fun rebuild() {
        val showHidden = _state.value.showHidden
        val showIgnored = _state.value.showIgnored
        val out = mutableListOf<FileNode>()

        fun walk(dir: String, depth: Int) {
            val entries = children[dir] ?: return
            for (entry in entries) {
                if (entry.isHidden && !showHidden) continue
                if (entry.isGitIgnored && !showIgnored) continue
                val path = "$dir/${entry.name}"
                val isOpen = path in expanded
                out += FileNode(
                    path = path,
                    entry = entry,
                    depth = depth,
                    expanded = isOpen,
                    loadingChildren = path in loadingPaths,
                )
                if (isOpen) walk(path, depth + 1)
            }
        }

        walk(root, 0)
        _state.update { it.copy(nodes = out) }
    }
}
