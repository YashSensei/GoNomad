package dev.gonomad.app.feature.pair

import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.gonomad.app.ffi.SessionRepository
import dev.gonomad.app.ui.common.ErrorAction
import dev.gonomad.app.ui.common.ErrorPresentation
import dev.gonomad.app.ui.common.ErrorSite
import dev.gonomad.app.ui.common.toPresentation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

sealed interface PairStep {
    /** The honest explanation of what pairing grants. */
    data object Intro : PairStep

    data object Scanning : PairStep
    data object ManualEntry : PairStep

    /** Noise handshake in flight. */
    data object Handshaking : PairStep

    /** Six digits on screen, awaiting a human comparison. */
    data class ConfirmSas(val sas: String) : PairStep

    data object Committing : PairStep
    data object Paired : PairStep
}

data class PairUiState(
    val step: PairStep = PairStep.Intro,
    val manualCode: String = "",
    val deviceName: String = "",
    val error: ErrorPresentation? = null,
    val cameraPermanentlyDenied: Boolean = false,
)

/**
 * Drives the real pairing handshake.
 *
 * The order is fixed by the protocol and by §9.2: `beginPairing` runs the Noise
 * exchange and returns a SAS but registers nothing; the user compares six digits;
 * only then does `confirmPairing` perform the authenticated `sys.register` that
 * actually stores anything. Every failure between those points leaves the phone
 * unpaired, so there is no partial state to clean up.
 */
class PairViewModel(private val session: SessionRepository) : ViewModel() {

    private val _state = MutableStateFlow(PairUiState(deviceName = defaultDeviceName()))
    val state: StateFlow<PairUiState> = _state.asStateFlow()

    fun startScanning() {
        _state.update { it.copy(step = PairStep.Scanning, error = null) }
    }

    fun startManualEntry() {
        _state.update { it.copy(step = PairStep.ManualEntry, error = null) }
    }

    fun onManualCodeChanged(code: String) {
        // The machine prints an uppercase base32 code; normalising here keeps the
        // field forgiving without the ViewModel knowing the alphabet.
        _state.update { it.copy(manualCode = code.uppercase().filter { c -> !c.isWhitespace() }) }
    }

    /**
     * The name *this phone* will carry on the machine's device list and in its
     * audit log — not the machine's name. Editable because `Build.MODEL` is
     * "SM-S911B" on half the devices in the world, and a device list you cannot
     * read is a device list you will not revoke from.
     */
    fun onDeviceNameChanged(name: String) {
        _state.update { it.copy(deviceName = name.take(MAX_DEVICE_NAME)) }
    }

    fun onCameraPermissionDenied(permanently: Boolean) {
        _state.update {
            it.copy(step = PairStep.Intro, cameraPermanentlyDenied = permanently)
        }
    }

    fun submitManualCode() = beginPairing(_state.value.manualCode)

    /**
     * A scan can fire several frames in a row for the same code; only the first
     * one may start a handshake, because the pairing window is single use.
     */
    fun onQrScanned(payload: String) {
        if (_state.value.step != PairStep.Scanning) return
        beginPairing(payload)
    }

    /**
     * Runs the handshake.
     *
     * Failures here are read with [ErrorSite.Pairing]. Three distinct outcomes
     * reach this point and each wants different advice: a payload that is not a
     * GoNomad code at all arrives as `Protocol`, a wrong or expired code arrives as
     * `PairingRejected` (§19 R24 — the machine answered and the phone could not
     * authenticate the answer), and a machine that was never reached arrives as
     * `Transport`. Only the middle one is a reason to rescan.
     */
    private fun beginPairing(payload: String) {
        _state.update { it.copy(step = PairStep.Handshaking, error = null) }
        viewModelScope.launch {
            runCatching { session.client.beginPairing(payload) }
                .onSuccess { sas -> _state.update { it.copy(step = PairStep.ConfirmSas(sas)) } }
                .onFailure { e ->
                    _state.update {
                        it.copy(
                            step = PairStep.Intro,
                            error = e.toPresentation(ErrorSite.Pairing),
                        )
                    }
                }
        }
    }

    /** The user compared the digits and they matched. */
    fun confirmSasMatches() {
        val name = _state.value.deviceName.trim().ifBlank { defaultDeviceName() }
        _state.update { it.copy(step = PairStep.Committing) }
        viewModelScope.launch {
            runCatching { session.client.confirmPairing(name) }
                .onSuccess { _state.update { it.copy(step = PairStep.Paired) } }
                .onFailure { e ->
                    _state.update {
                        it.copy(
                            step = PairStep.Intro,
                            error = e.toPresentation(ErrorSite.Pairing),
                        )
                    }
                }
        }
    }

    /**
     * The digits did not match. This is the interesting branch: it means someone
     * else completed the handshake, so the attempt is abandoned rather than
     * retried silently.
     */
    fun rejectSas() {
        session.client.cancelPairing()
        _state.update {
            it.copy(
                step = PairStep.Intro,
                error = ErrorPresentation(
                    title = "Pairing abandoned",
                    detail = "The digits did not match, which means the code you scanned was " +
                        "not from that machine. Generate a fresh QR with `gonomad pair` and " +
                        "scan it directly from the screen.",
                    actionLabel = null,
                    action = ErrorAction.None,
                ),
            )
        }
    }

    fun cancel() {
        session.client.cancelPairing()
        _state.update { it.copy(step = PairStep.Intro, error = null) }
    }

    private companion object {
        const val MAX_DEVICE_NAME = 40

        fun defaultDeviceName(): String =
            listOf(Build.MANUFACTURER.replaceFirstChar { it.uppercase() }, Build.MODEL)
                .filter { it.isNotBlank() }
                .joinToString(" ")
                .ifBlank { "Android phone" }
    }
}
