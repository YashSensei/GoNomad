package dev.gonomad.app.ffi.fake

import dev.gonomad.ffi.ConnState
import dev.gonomad.ffi.DeviceInfo
import dev.gonomad.ffi.DirEntry
import dev.gonomad.ffi.EntryKind
import dev.gonomad.ffi.FileContent
import dev.gonomad.ffi.GonomadClientInterface
import dev.gonomad.ffi.GonomadException
import dev.gonomad.ffi.Status
import dev.gonomad.ffi.StatusListener
import dev.gonomad.ffi.TerminalHandle
import dev.gonomad.ffi.TerminalListener
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.abs
import kotlin.random.Random

/**
 * An in-process stand-in for the Rust core, selected by
 * [dev.gonomad.app.ffi.ClientProvider.USE_FAKE] (which defaults to `false`).
 *
 * It implements the **generated** [GonomadClientInterface], not a hand-written
 * copy of it, so the compiler now enforces that the fake and the real client are
 * the same shape. When the Rust API changes, this file stops compiling — which is
 * the entire point of the arrangement.
 *
 * It is not a protocol simulator. It is a source of believable data with
 * believable latency so every screen, empty state, and error path can be judged
 * in a `@Preview` or without a daemon on the network. Everything it returns is
 * invented.
 */
class FakeGonomadClient(private val stateDir: String) : GonomadClientInterface {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private val pairingFile = File(stateDir, PAIRING_FILE)

    @Volatile
    private var daemon: DeviceInfo? = readPairing()

    @Volatile
    private var pendingSas: String? = null

    /** What this phone is called on the machine's device list. */
    @Volatile
    private var registeredAs: String? = null

    @Volatile
    private var current: Status = Status(
        state = if (daemon != null) ConnState.DISCONNECTED else ConnState.UNPAIRED,
        daemonName = daemon?.name,
        rttMs = null,
        transport = null,
    )

    @Volatile
    private var statusListener: StatusListener? = null

    @Volatile
    private var terminalListener: TerminalListener? = null

    private val nextPtyId = AtomicLong(1)
    private val shells = LinkedHashMap<ULong, FakeShell>()
    private var rttJob: Job? = null

    // --- pairing -------------------------------------------------------------

    override fun isPaired(): Boolean = daemon != null

    override fun pairedDaemon(): DeviceInfo? = daemon

    override suspend fun beginPairing(qrPayload: String): String {
        // A Noise handshake plus a round trip is not instant, and the UI needs a
        // progress state that lasts long enough to read.
        delay(900)

        val payload = qrPayload.trim()
        if (payload.isEmpty()) {
            throw GonomadException.Protocol("The pairing payload was empty.")
        }
        // The real payload is `gonomad://pair?...` and the real check is a Noise
        // handshake, not a string match. The fake accepts anything long enough so
        // that scanning whatever QR is to hand still demonstrates the flow; the
        // rejections below exist so the error paths stay reachable with no daemon.
        if (payload.length < 8) {
            throw GonomadException.Protocol("That is too short to be a pairing payload.")
        }
        if (payload.contains("expired")) {
            throw GonomadException.Protocol("That pairing window has expired.")
        }
        // A wrong code shows up as Transport, exactly as it does for real (§19 R24).
        if (payload.contains("wrong")) {
            throw GonomadException.Transport("The machine would not register this device.")
        }

        // A real SAS is derived from the handshake hash. This derives from the
        // payload instead, so the same QR always yields the same digits and the
        // screen is demonstrable.
        val h = payload.fold(0) { acc, c -> acc * 31 + c.code }
        val digits = (abs(h) % 1_000_000).toString().padStart(6, '0')
        return "${digits.take(3)} ${digits.drop(3)}".also { pendingSas = it }
    }

    /**
     * [deviceName] is the name *this phone* registers under on the machine's
     * device list — it is not the machine's name. `pairedDaemon()` returns the
     * machine, so the hostname reported here is the laptop's.
     */
    override suspend fun confirmPairing(deviceName: String) {
        if (pendingSas == null) throw GonomadException.Protocol("No pairing is in progress.")
        delay(600)
        registeredAs = deviceName
        val info = DeviceInfo(
            deviceId = "7f3a91c2e40b",
            name = "DESKTOP-7QK4L1",
            pairedAt = System.currentTimeMillis(),
            lastSeen = System.currentTimeMillis(),
        )
        daemon = info
        pendingSas = null
        writePairing(info)
        emit(current.copy(state = ConnState.DISCONNECTED, daemonName = info.name))
    }

    override fun cancelPairing() {
        pendingSas = null
    }

    override fun unpair() {
        rttJob?.cancel()
        rttJob = null
        daemon = null
        pendingSas = null
        registeredAs = null
        shells.clear()
        runCatching { pairingFile.delete() }
        emit(Status(ConnState.UNPAIRED, null, null, null))
    }

    // --- connection ----------------------------------------------------------

    override suspend fun connect() {
        val info = daemon ?: throw GonomadException.NotPaired()
        emit(
            current.copy(
                state = ConnState.CONNECTING,
                daemonName = info.name,
                transport = null,
                rttMs = null,
            ),
        )
        delay(1_100)
        emit(
            Status(
                state = ConnState.CONNECTED,
                daemonName = info.name,
                rttMs = Random.nextInt(6, 18).toUInt(),
                transport = "LAN",
            ),
        )
        startRttJitter()
    }

    override fun disconnect() {
        rttJob?.cancel()
        rttJob = null
        emit(current.copy(state = ConnState.DISCONNECTED, rttMs = null, transport = null))
    }

    override fun status(): Status = current

    override fun observeStatus(listener: StatusListener) {
        statusListener = listener
        listener.onStatus(current)
    }

    /** Makes the RTT read on Home look like a measurement, not a constant. */
    private fun startRttJitter() {
        rttJob?.cancel()
        rttJob = scope.launch {
            while (isActive) {
                delay(4_000)
                if (current.state != ConnState.CONNECTED) continue
                emit(current.copy(rttMs = Random.nextInt(5, 26).toUInt()))
            }
        }
    }

    private fun emit(next: Status) {
        current = next
        statusListener?.onStatus(next)
    }

    private fun requireConnected() {
        if (daemon == null) throw GonomadException.NotPaired()
        if (current.state != ConnState.CONNECTED) {
            throw GonomadException.Transport(
                "No session with ${daemon?.name ?: "your machine"}.",
            )
        }
    }

    // --- filesystem ----------------------------------------------------------

    override suspend fun workspaceRoots(): List<String> {
        requireConnected()
        delay(120)
        return FakeWorkspace.roots
    }

    override suspend fun listDir(path: String): List<DirEntry> {
        requireConnected()
        delay(Random.nextLong(180, 420))
        return FakeWorkspace.dirs[path.trimEnd('/')] ?: throw GonomadException.NotFound()
    }

    override suspend fun readFile(path: String): FileContent {
        requireConnected()
        delay(Random.nextLong(220, 500))

        val key = path.trimEnd('/')
        if (key in FakeWorkspace.denylisted) {
            // The daemon refuses before reading a byte: this needs `fs:secrets`
            // plus a live biometric.
            throw GonomadException.Denied("fs:secrets")
        }
        if (key in FakeWorkspace.binary) {
            // The real daemon reports a non-UTF-8 file as a bad request, which
            // the FFI maps to Protocol — not Unsupported, which is version skew.
            throw GonomadException.Protocol("That file is not valid UTF-8 text.")
        }

        val entry = entryFor(key) ?: throw GonomadException.NotFound()
        if (entry.kind == EntryKind.DIRECTORY) {
            throw GonomadException.Protocol("That is a directory, not a file.")
        }

        val text = FakeWorkspace.files[key]
            ?: FakeFileBodies.placeholder(key, entry.sizeBytes?.toLong() ?: 0L)
        return FileContent(
            path = key,
            text = text,
            contentHash = FakeWorkspace.contentHash(key, text),
            truncated = key in FakeWorkspace.truncated,
        )
    }

    private fun entryFor(path: String): DirEntry? {
        val parent = path.substringBeforeLast('/', "")
        val name = path.substringAfterLast('/')
        return FakeWorkspace.dirs[parent]?.firstOrNull { it.name == name }
    }

    // --- terminal ------------------------------------------------------------

    override suspend fun spawnTerminal(cwd: String?): TerminalHandle {
        requireConnected()
        delay(340)
        val id = nextPtyId.getAndIncrement().toULong()
        val shell = FakeShell(
            ptyId = id,
            startCwd = cwd ?: FakeWorkspace.ROOT_GONOMAD,
            clientLabel = registeredAs ?: "this device",
        ) { frame ->
            terminalListener?.onFrame(frame)
        }
        shells[id] = shell
        // The contract returns the first frame with the id, so the caller never
        // has to render a blank screen while waiting for a poll.
        return TerminalHandle(ptyId = id, initial = shell.banner())
    }

    override suspend fun sendInput(ptyId: ULong, data: String) {
        requireConnected()
        val shell = shells[ptyId] ?: throw GonomadException.NotFound()
        shell.feed(data)
    }

    override suspend fun resizeTerminal(ptyId: ULong, cols: UShort, rows: UShort) {
        requireConnected()
        val shell = shells[ptyId] ?: throw GonomadException.NotFound()
        shell.resize(cols.toInt(), rows.toInt())
    }

    override suspend fun closeTerminal(ptyId: ULong) {
        shells.remove(ptyId) ?: throw GonomadException.NotFound()
    }

    override fun observeTerminal(listener: TerminalListener) {
        terminalListener = listener
    }

    // --- pairing persistence -------------------------------------------------
    // The real client keeps this in its own state directory. A tiny file is
    // enough for the fake to survive a cold start, which matters because
    // re-pairing on every launch would hide every other screen.

    private fun readPairing(): DeviceInfo? = runCatching {
        val f = File(stateDir, PAIRING_FILE)
        if (!f.exists()) return@runCatching null
        // One field per line: no delimiter to escape, and trivially readable with
        // `adb shell run-as` while debugging.
        val parts = f.readLines()
        if (parts.size < 3) return@runCatching null
        DeviceInfo(
            deviceId = parts[0],
            name = parts[1],
            pairedAt = parts[2].toLong(),
            lastSeen = System.currentTimeMillis(),
        )
    }.getOrNull()

    private fun writePairing(info: DeviceInfo) {
        runCatching {
            pairingFile.writeText(
                listOf(info.deviceId, info.name, info.pairedAt.toString())
                    .joinToString("\n"),
            )
        }
    }

    private companion object {
        const val PAIRING_FILE = "paired.txt"
    }
}
