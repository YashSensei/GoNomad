package dev.gonomad.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import dev.gonomad.app.ui.theme.GoNomadTheme
import dev.gonomad.app.ui.theme.Ink

/**
 * Single activity, per ARCHITECTURE.md 6.1. Every screen is a composable
 * destination; there is no fragment, no second activity, and no XML layout.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        // Edge-to-edge is mandatory on targetSdk 35; declaring the bar styles
        // up front stops the system from drawing a light scrim over our dark
        // background on OEM skins.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Ink.toArgb()),
            navigationBarStyle = SystemBarStyle.dark(Ink.toArgb()),
        )
        super.onCreate(savedInstanceState)

        setContent {
            GoNomadTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    GoNomadApp()
                }
            }
        }
    }
}
