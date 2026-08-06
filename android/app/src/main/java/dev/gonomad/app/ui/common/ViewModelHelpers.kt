package dev.gonomad.app.ui.common

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import dev.gonomad.app.ffi.ClientProvider
import dev.gonomad.app.ffi.SessionRepository
import dev.gonomad.app.ffi.TerminalsRepository

/**
 * There are two dependencies in this app — [SessionRepository] and
 * [TerminalsRepository] — so a DI framework would be more machinery than the
 * graph it manages. This is the whole of it.
 */
@Composable
fun rememberSession(): SessionRepository =
    ClientProvider.session(LocalContext.current.applicationContext)

/**
 * The process-wide set of open terminals.
 *
 * Deliberately not held by a `ViewModel`: PTYs outlive every screen, so the thing
 * that tracks them has to outlive every `ViewModelStoreOwner` too.
 */
@Composable
fun rememberTerminals(): TerminalsRepository =
    ClientProvider.terminals(LocalContext.current.applicationContext)

@Composable
inline fun <reified VM : ViewModel> scopedViewModel(
    key: String? = null,
    crossinline create: (SessionRepository) -> VM,
): VM {
    val session = rememberSession()
    return viewModel(
        key = key,
        factory = viewModelFactory {
            initializer { create(session) }
        },
    )
}
