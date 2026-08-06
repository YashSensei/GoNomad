package dev.gonomad.app

import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.runtime.Composable
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.toRoute
import dev.gonomad.app.feature.files.FilesScreen
import dev.gonomad.app.feature.home.HomeScreen
import dev.gonomad.app.feature.pair.PairScreen
import dev.gonomad.app.feature.settings.SettingsScreen
import dev.gonomad.app.feature.terminal.TerminalScreen
import dev.gonomad.app.feature.viewer.ViewerScreen
import dev.gonomad.app.ui.common.rememberSession
import dev.gonomad.app.ui.nav.FilesRoute
import dev.gonomad.app.ui.nav.HomeRoute
import dev.gonomad.app.ui.nav.PairRoute
import dev.gonomad.app.ui.nav.SettingsRoute
import dev.gonomad.app.ui.nav.TerminalRoute
import dev.gonomad.app.ui.nav.ViewerRoute

private const val TRANSITION_MS = 220

@Composable
fun GoNomadApp(navController: NavHostController = rememberNavController()) {
    val session = rememberSession()

    // The only routing decision in the app, and it is a fact about local state
    // rather than protocol state: is there a stored daemon at all?
    val start: Any = if (session.client.isPaired()) HomeRoute else PairRoute

    NavHost(
        navController = navController,
        startDestination = start,
        // Restrained motion: a short horizontal slide with a cross-fade. Big
        // spatial transitions on a dark UI read as flicker.
        enterTransition = {
            slideInHorizontally(tween(TRANSITION_MS)) { it / 6 } + fadeIn(tween(TRANSITION_MS))
        },
        exitTransition = { fadeOut(tween(TRANSITION_MS / 2)) },
        popEnterTransition = { fadeIn(tween(TRANSITION_MS)) },
        popExitTransition = {
            slideOutHorizontally(tween(TRANSITION_MS)) { it / 6 } + fadeOut(tween(TRANSITION_MS))
        },
    ) {
        composable<PairRoute> {
            PairScreen(
                onPaired = {
                    navController.navigate(HomeRoute) {
                        popUpTo(PairRoute) { inclusive = true }
                    }
                },
            )
        }

        composable<HomeRoute> {
            HomeScreen(
                onOpenFiles = { root -> navController.navigate(FilesRoute(root)) },
                onOpenTerminal = { cwd -> navController.navigate(TerminalRoute(cwd)) },
                onOpenFile = { path -> navController.navigate(ViewerRoute(path)) },
                onOpenSettings = { navController.navigate(SettingsRoute) },
            )
        }

        composable<FilesRoute> { entry ->
            val route = entry.toRoute<FilesRoute>()
            FilesScreen(
                root = route.path,
                onBack = navController::popBackStack,
                onOpenFile = { path -> navController.navigate(ViewerRoute(path)) },
                onOpenTerminal = { cwd -> navController.navigate(TerminalRoute(cwd)) },
            )
        }

        composable<ViewerRoute> { entry ->
            val route = entry.toRoute<ViewerRoute>()
            ViewerScreen(path = route.path, onBack = navController::popBackStack)
        }

        composable<TerminalRoute> { entry ->
            val route = entry.toRoute<TerminalRoute>()
            TerminalScreen(cwd = route.cwd, onBack = navController::popBackStack)
        }

        composable<SettingsRoute> {
            SettingsScreen(
                onBack = navController::popBackStack,
                onUnpaired = {
                    navController.navigate(PairRoute) {
                        popUpTo(HomeRoute) { inclusive = true }
                    }
                },
            )
        }
    }
}
