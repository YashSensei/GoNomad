package dev.gonomad.app.ui.common

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import dev.gonomad.app.ffi.ClientProvider
import dev.gonomad.app.ffi.SessionRepository

/**
 * There is one dependency in this app — [SessionRepository] — so a DI framework
 * would be more machinery than the graph it manages. This is the whole of it.
 */
@Composable
fun rememberSession(): SessionRepository =
    ClientProvider.session(LocalContext.current.applicationContext)

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
