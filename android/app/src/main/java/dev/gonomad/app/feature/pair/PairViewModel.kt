package dev.gonomad.app.feature.pair

import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.gonomad.app.ffi.SessionRepository
import dev.gonomad.app.ui.common.ErrorAction
import dev.gonomad.app.ui.common.ErrorPresentation
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
    val error: ErrorPresentation? = null,
    val cameraPermanentlyDenied: Boolean = false,
)

class PairViewModel(private val session: SessionRepository) : ViewModel() {

    private val _state = MutableStateFlow(PairUiState())
    val state: StateFlow<PairUiState> = _state.asStateFlow()

    /** The name shown on the laptop's device list for this phone. */
    private val deviceName: String =
        listOf(Build.MANUFACTURER.replaceFirstChar { it.uppercase() }, Build.MODEL)
            .filter { it.isNotBlank() }
            .joinToString(" ")
            .ifBlank { "Android phone" }

    fun startScanning() {
        _state.update { it.copy(step = PairStep.Scanning, error = null) }
    }

    fun startManualEntry() {
        _state.update { it.copy(step = PairStep.ManualEntry, error = null) }
    }

    fun onManualCodeChanged(code: String) {
        // The daemon prints an uppercase base32 code; normalising here keeps
        // the field forgiving without the ViewModel knowing the alphabet.
        _state.update { it.copy(manualCode = code.uppercase().filter { c -> !c.isWhitespace() }) }
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

    private fun beginPairing(payload: String) {
        _state.update { it.copy(step = PairStep.Handshaking, error = null) }
        viewModelScope.launch {
            runCatching { session.client.beginPairing(payload) }
                .onSuccess { sas -> _state.update { it.copy(step = PairStep.ConfirmSas(sas)) } }
                .onFailure { e ->
                    _state.update {
                        it.copy(step = PairStep.Intro, error = e.toPresentation())
                    }
                }
        }
    }

    /** The user compared the digits and they matched. */
    fun confirmSasMatches() {
        _state.update { it.copy(step = PairStep.Committing) }
        viewModelScope.launch {
            runCatching { session.client.confirmPairing(deviceName) }
                .onSuccess { _state.update { it.copy(step = PairStep.Paired) } }
                .onFailure { e ->
                    _state.update { it.copy(step = PairStep.Intro, error = e.toPresentation()) }
                }
        }
    }

    /**
     * The digits did not match. This is the interesting branch: it means
     * someone else completed the handshake, so the attempt is abandoned rather
     * than retried silently.
     */
    fun rejectSas() {
        session.client.cancelPairing()
        _state.update {
            it.copy(
                step = PairStep.Intro,
                error = ErrorPresentation(
                    title = "Pairing abandoned",
                    detail = "The digits did not match, which means the code you scanned " +
                        "was not from that laptop. Generate a fresh QR with `gonomad pair` " +
                        "and scan it directly from the screen.",
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

    fun dismissError() {
        _state.update { it.copy(error = null) }
    }
}
