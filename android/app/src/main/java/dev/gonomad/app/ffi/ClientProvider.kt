package dev.gonomad.app.ffi

import android.content.Context
import dev.gonomad.app.ffi.fake.FakeGonomadClient
import java.io.File

/**
 * The single seam between the app and the core.
 *
 * Flip [USE_FAKE] to `false` once `gonomad-ffi` ships its UniFFI bindings and
 * replace the one line in [createClient] with:
 *
 * ```
 * dev.gonomad.ffi.GonomadClient.create(stateDir)
 * ```
 *
 * Nothing else in the app knows which implementation it is talking to.
 */
object ClientProvider {

    /**
     * `true` while the Rust core is being written by the other half of the
     * team. The rest of the app is written against [GonomadClient] only, so
     * this is the whole of the integration surface.
     */
    const val USE_FAKE: Boolean = true

    @Volatile
    private var session: SessionRepository? = null

    fun session(context: Context): SessionRepository =
        session ?: synchronized(this) {
            session ?: SessionRepository(createClient(context)).also { session = it }
        }

    private fun createClient(context: Context): GonomadClient {
        // Device keys and pairing state live in app-private storage, which is
        // excluded from backup and device transfer (see data_extraction_rules).
        val stateDir = File(context.applicationContext.filesDir, "gonomad")
            .apply { mkdirs() }
            .absolutePath

        return if (USE_FAKE) {
            FakeGonomadClient(stateDir)
        } else {
            error("gonomad-ffi is not wired up yet; set USE_FAKE = true")
        }
    }
}
