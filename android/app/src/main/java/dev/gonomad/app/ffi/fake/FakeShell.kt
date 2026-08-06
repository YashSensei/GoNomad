package dev.gonomad.app.ffi.fake

import dev.gonomad.ffi.EntryKind
import dev.gonomad.ffi.TerminalFrame
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * A toy shell behind the fake PTY.
 *
 * The real slice ships a headless VT emulator on the laptop and sends rendered
 * screens (`TerminalFrame.screen`). This produces the same shape of output for
 * a handful of commands so the terminal screen — and above all the accessory
 * key row — can be exercised on a real device.
 *
 * It is a PowerShell-flavoured prompt because the host is Windows-first
 * (ARCHITECTURE.md 8.2, ConPTY).
 */
internal class FakeShell(
    private val ptyId: ULong,
    startCwd: String,
    private val clientLabel: String,
    private val onFrame: (TerminalFrame) -> Unit,
) {
    private val lines = ArrayDeque<String>()
    private var cwd = startCwd
    private var input = StringBuilder()
    private val history = mutableListOf<String>()
    private var historyCursor = -1
    private var cols = 80

    /** Returns the first frame, which `spawnTerminal` hands back with the id. */
    fun banner(): TerminalFrame {
        emitLine("Windows PowerShell 7.4.5")
        emitLine("(c) Microsoft Corporation. All rights reserved.")
        emitLine("")
        emitLine("gonomad: pty $ptyId attached to $clientLabel over LAN")
        emitLine("gonomad: scrollback lives on the daemon and survives disconnects")
        emitLine("Type 'help' for the commands this fake core understands.")
        emitLine("")
        return push()
    }

    fun resize(newCols: Int, @Suppress("UNUSED_PARAMETER") newRows: Int) {
        cols = newCols.coerceIn(20, 400)
        push()
    }

    /**
     * Accepts raw PTY input, exactly as the real `pty.input` would: printable
     * text, control characters from the accessory row, and CSI arrow keys.
     */
    fun feed(data: String) {
        var i = 0
        while (i < data.length) {
            val c = data[i]
            when {
                data.startsWith(ESC_UP, i) -> { recallHistory(-1); i += ESC_UP.length; continue }
                data.startsWith(ESC_DOWN, i) -> { recallHistory(1); i += ESC_DOWN.length; continue }
                data.startsWith(ESC_RIGHT, i) || data.startsWith(ESC_LEFT, i) -> { i += 3; continue }

                c == '\u0003' -> { // Ctrl+C
                    emitLine(prompt() + input.toString() + "^C")
                    input = StringBuilder()
                }
                c == '\u0004' -> { // Ctrl+D
                    emitLine(prompt() + input.toString())
                    emitLine("exit: the daemon keeps this PTY alive across disconnects.")
                    input = StringBuilder()
                }
                c == '\u000C' -> clear() // Ctrl+L
                c == '\u001B' -> input = StringBuilder() // bare Esc kills the line
                c == '\t' -> input.append("    ")
                c == '\b' || c == '\u007F' -> if (input.isNotEmpty()) input.deleteAt(input.length - 1)
                c == '\r' || c == '\n' -> run()
                c.code >= 0x20 -> input.append(c)
            }
            i++
        }
        push()
    }

    private fun recallHistory(delta: Int) {
        if (history.isEmpty()) return
        historyCursor = (historyCursor + delta).coerceIn(0, history.size - 1)
        input = StringBuilder(history[historyCursor])
    }

    private fun run() {
        val line = input.toString()
        input = StringBuilder()
        emitLine(prompt() + line)
        val cmd = line.trim()
        if (cmd.isNotEmpty()) {
            history += cmd
            historyCursor = history.size
        }
        if (cmd.isEmpty()) return

        val argv = cmd.split(Regex("\\s+"))
        when (argv[0]) {
            "help" -> help()
            "clear", "cls" -> clear()
            "pwd" -> emitLine(cwd.replace('/', '\\'))
            "cd" -> cd(argv.getOrNull(1))
            "ls", "dir", "gci" -> ls()
            "cat", "type", "gc" -> cat(argv.getOrNull(1))
            "echo" -> emitLine(argv.drop(1).joinToString(" "))
            "whoami" -> emitLine("desktop-7qk4l1\\dev")
            "date" -> emitLine(stamp())
            "git" -> git(argv.drop(1))
            "cargo" -> cargo(argv.drop(1))
            "exit" -> emitLine("This PTY outlives the connection. Close it from the terminal menu.")
            else -> {
                emitLine("${argv[0]} : The term '${argv[0]}' is not recognized as a name of a")
                emitLine("cmdlet, function, script file, or operable program.")
                emitLine("Check the spelling of the name, or if a path was included, verify that")
                emitLine("the path is correct and try again.")
            }
        }
    }

    private fun help() {
        emitLine("This is a fake core. It understands:")
        emitLine("  ls | dir        list the current directory")
        emitLine("  cd <dir>        change directory ('..' works)")
        emitLine("  cat <file>      print a file")
        emitLine("  pwd             print the working directory")
        emitLine("  git status|log|branch")
        emitLine("  cargo build|test")
        emitLine("  echo, whoami, date, clear")
        emitLine("Everything else echoes a PowerShell not-recognized error.")
    }

    private fun clear() {
        lines.clear()
    }

    private fun cd(target: String?) {
        if (target == null || target == "~") {
            cwd = FakeWorkspace.ROOT_GONOMAD
            return
        }
        val next = when {
            target == ".." -> cwd.substringBeforeLast('/', cwd)
            target.startsWith("C:/") || target.startsWith("/") -> target.trimEnd('/')
            else -> "$cwd/${target.trim('/')}"
        }
        if (FakeWorkspace.dirs.containsKey(next)) {
            cwd = next
        } else {
            emitLine("cd : Cannot find path '${next.replace('/', '\\')}' because it does not exist.")
        }
    }

    private fun ls() {
        val entries = FakeWorkspace.dirs[cwd]
        if (entries == null) {
            emitLine("Get-ChildItem : Cannot find path '${cwd.replace('/', '\\')}'.")
            return
        }
        emitLine("")
        emitLine("    Directory: ${cwd.replace('/', '\\')}")
        emitLine("")
        emitLine("Mode                 LastWriteTime         Length Name")
        emitLine("----                 -------------         ------ ----")
        for (e in entries) {
            val mode = when (e.kind) {
                EntryKind.DIRECTORY -> "d----"
                EntryKind.SYMLINK -> "l----"
                EntryKind.FILE -> "-a---"
            }
            val time = e.modifiedMs?.let { stamp(it) } ?: "".padEnd(19)
            val size = e.sizeBytes?.toString() ?: ""
            emitLine("$mode  ${time.padEnd(20)} ${size.padStart(12)} ${e.name}")
        }
        emitLine("")
    }

    private fun cat(name: String?) {
        if (name == null) {
            emitLine("cat : Missing an argument for parameter 'Path'.")
            return
        }
        val path = if (name.startsWith("C:/")) name else "$cwd/${name.trim('/')}"
        when {
            path in FakeWorkspace.denylisted -> {
                emitLine("gonomad: denied — 'fs:secrets' is not granted to this device.")
                emitLine("         The path matches the secret denylist. Grant the capability")
                emitLine("         at the laptop and approve with a biometric to read it.")
            }
            path in FakeWorkspace.binary ->
                emitLine("gonomad: refusing to print a binary file.")
            else -> {
                val body = FakeWorkspace.files[path]
                if (body == null) {
                    emitLine("cat : Cannot find path '${path.replace('/', '\\')}'.")
                } else {
                    body.lineSequence().take(60).forEach(::emitLine)
                }
            }
        }
    }

    private fun git(args: List<String>) {
        when (args.firstOrNull()) {
            "status" -> {
                emitLine("On branch feat/ffi-contract")
                emitLine("Your branch is ahead of 'origin/main' by 3 commits.")
                emitLine("  (use \"git push\" to publish your local commits)")
                emitLine("")
                emitLine("Changes not staged for commit:")
                emitLine("  (use \"git add <file>...\" to update what will be committed)")
                emitLine("        modified:   crates/gonomad-core/src/pairing.rs")
                emitLine("        modified:   docs/ffi-contract.md")
                emitLine("")
                emitLine("Untracked files:")
                emitLine("  (use \"git add <file>...\" to include in what will be committed)")
                emitLine("        android/")
                emitLine("")
                emitLine("no changes added to commit (use \"git add\" and/or \"git commit -a\")")
            }
            "log" -> {
                emitLine("9f2c1ab (HEAD -> feat/ffi-contract) proto: bound MAX_FRAME before alloc")
                emitLine("41ed093 core: derive SAS from the handshake hash, not the psk")
                emitLine("c07b5de policy: exempt .env.example from the secret denylist")
                emitLine("2a9f004 (origin/main) store: hash-chain the audit log")
                emitLine("8be1177 chore: pin the toolchain to 1.75")
            }
            "branch" -> {
                emitLine("* feat/ffi-contract")
                emitLine("  main")
                emitLine("  spike/iroh-transport")
            }
            "diff" -> {
                emitLine("diff --git a/docs/ffi-contract.md b/docs/ffi-contract.md")
                emitLine("index 3f1b2c4..9a7de10 100644")
                emitLine("--- a/docs/ffi-contract.md")
                emitLine("+++ b/docs/ffi-contract.md")
                emitLine("@@ -101,6 +101,7 @@ class GonomadClient {")
                emitLine("     suspend fun beginPairing(qrPayload: String): String")
                emitLine("+    suspend fun confirmPairing(deviceName: String)")
                emitLine("     fun cancelPairing()")
            }
            null -> emitLine("usage: git <command> [<args>]")
            else -> emitLine("git: '${args[0]}' is not a git command. See 'git --help'.")
        }
    }

    private fun cargo(args: List<String>) {
        when (args.firstOrNull()) {
            "build" -> {
                emitLine("   Compiling gonomad-proto v0.1.0 (C:\\Users\\dev\\src\\gonomad\\crates\\gonomad-proto)")
                emitLine("   Compiling gonomad-core v0.1.0 (C:\\Users\\dev\\src\\gonomad\\crates\\gonomad-core)")
                emitLine("   Compiling gonomad-policy v0.1.0 (C:\\Users\\dev\\src\\gonomad\\crates\\gonomad-policy)")
                emitLine("    Finished `dev` profile [unoptimized + debuginfo] target(s) in 11.42s")
            }
            "test" -> {
                emitLine("running 24 tests")
                emitLine("test codec::tests::roundtrip ... ok")
                emitLine("test codec::tests::partial_frame_is_not_an_error ... ok")
                emitLine("test pairing::tests::window_expires_at_120s ... ok")
                emitLine("test pairing::tests::sas_mismatch_aborts ... ok")
                emitLine("test policy::denylist::env_example_is_not_secret ... ok")
                emitLine("")
                emitLine("test result: ok. 24 passed; 0 failed; 0 ignored; finished in 0.31s")
            }
            else -> emitLine("error: no such command: `${args.firstOrNull() ?: ""}`")
        }
    }

    // --- screen ---------------------------------------------------------------

    private fun prompt() = "PS ${cwd.replace('/', '\\')}> "

    private fun emitLine(s: String) {
        lines.addLast(s)
        while (lines.size > SCROLLBACK) lines.removeFirst()
    }

    /// The current screen, without notifying the listener.
    ///
    /// Used when reattaching after a reconnect: the caller wants the frame
    /// returned to it, and pushing to the listener as well would deliver the same
    /// screen twice.
    fun currentFrame(): TerminalFrame {
        val current = prompt() + input.toString()
        val screen = (lines + current).joinToString("\n")
        return TerminalFrame(
            ptyId = ptyId,
            screen = screen,
            cursorRow = lines.size.coerceAtMost(UShort.MAX_VALUE.toInt()).toUShort(),
            cursorCol = current.length.coerceAtMost(UShort.MAX_VALUE.toInt()).toUShort(),
        )
    }

    private fun push(): TerminalFrame {
        val current = prompt() + input.toString()
        val screen = (lines + current).joinToString("\n")
        val frame = TerminalFrame(
            ptyId = ptyId,
            screen = screen,
            cursorRow = lines.size.coerceAtMost(UShort.MAX_VALUE.toInt()).toUShort(),
            cursorCol = current.length.coerceAtMost(UShort.MAX_VALUE.toInt()).toUShort(),
        )
        onFrame(frame)
        return frame
    }

    private fun stamp(ms: Long = System.currentTimeMillis()): String =
        FORMAT.format(Date(ms))

    private companion object {
        const val SCROLLBACK = 400
        const val ESC_UP = "\u001B[A"
        const val ESC_DOWN = "\u001B[B"
        const val ESC_RIGHT = "\u001B[C"
        const val ESC_LEFT = "\u001B[D"
        val FORMAT = SimpleDateFormat("dd/MM/yyyy  HH:mm", Locale.UK)
    }
}
