package dev.gonomad.app.ffi

import android.content.Context
import dev.gonomad.app.ffi.fake.FakeGonomadClient
import dev.gonomad.ffi.ConnState
import dev.gonomad.ffi.GonomadClient
import dev.gonomad.ffi.GonomadClientInterface
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/**
 * The single seam between the app and the core.
 *
 * There is no hand-written mirror of the API any more: the app codes against
 * `dev.gonomad.ffi.GonomadClientInterface`, which UniFFI generates from the Rust
 * source, and the generated `GonomadClient` class is what runs in a shipped
 * build. [FakeGonomadClient] implements the *same generated interface*, so both
 * satisfy one type and neither can drift from the other.
 *
 * Everything process-scoped is built here, in one place, in one order:
 * [SessionRepository] registers the core's two single-slot callbacks, and
 * [TerminalsRepository] fans the terminal one out to the tab UI.
 */
object ClientProvider {

    /**
     * `true` selects [FakeGonomadClient] instead of the Rust core.
     *
     * It exists for `@Preview` and for working on a screen with no daemon to
     * hand. It **defaults to `false`**: the point of the app is to talk to a
     * real machine, and a build that quietly renders canned data is worse than
     * one that visibly cannot connect.
     */
    const val USE_FAKE: Boolean = false

    @Volatile
    private var graph: Graph? = null

    private class Graph(
        val session: SessionRepository,
        val terminals: TerminalsRepository,
    )

    fun session(context: Context): SessionRepository = graph(context).session

    fun terminals(context: Context): TerminalsRepository = graph(context).terminals

    private fun graph(context: Context): Graph =
        graph ?: synchronized(this) {
            graph ?: build(context).also { graph = it }
        }

    private fun build(context: Context): Graph {
        val client = createClient(context)
        val session = SessionRepository(client)
        val terminals = TerminalsRepository(client, session.frames)

        // Reattach to the machine's terminals every time a connection comes up.
        //
        // Wired here, at process scope, rather than from the terminal screen: the
        // machine's PTYs keep running regardless of which screen the user is
        // looking at, so restoring them must not depend on them navigating to the
        // terminal tab. A build that only restored on visiting that screen would
        // show an empty tab row on Home and look like the work was lost.
        //
        // `distinctUntilChanged` on the state matters — the status flow also
        // carries RTT, which changes constantly, and re-running the restore on
        // every RTT tick would hammer the daemon with pty.list.
        scope.launch {
            session.status
                .map { it.state }
                .distinctUntilChanged()
                .filter { it == ConnState.CONNECTED }
                .collect { terminals.restoreFromMachine() }
        }

        return Graph(session, terminals)
    }

    /**
     * Scope for work that belongs to the process rather than to any screen.
     *
     * Never cancelled: it is exactly as long-lived as the singletons it drives.
     * `SupervisorJob` so a failure in one collector cannot take down the others.
     */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Builds the core.
     *
     * A `GonomadException.Protocol` from `create` means the state directory is
     * unusable or the stored identity is corrupt, and it is deliberately not
     * caught: the Rust side reports corruption rather than replacing it, because
     * regenerating the device key would silently orphan the pairing on the
     * laptop. Swallowing it here would turn "your key is damaged, re-pair" into
     * "pairing mysteriously stopped working".
     */
    private fun createClient(context: Context): GonomadClientInterface {
        // Device keys and pairing state live in app-private storage, which is
        // excluded from backup and device transfer (see data_extraction_rules).
        val stateDir = File(context.applicationContext.filesDir, "gonomad")
            .apply { mkdirs() }
            .absolutePath

        return if (USE_FAKE) {
            FakeGonomadClient(stateDir)
        } else {
            GonomadClient.create(stateDir)
        }
    }
}
