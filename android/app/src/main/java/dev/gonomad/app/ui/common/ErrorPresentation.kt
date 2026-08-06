package dev.gonomad.app.ui.common

import dev.gonomad.app.ffi.GonomadError

/**
 * One rendering per member of the closed error enum.
 *
 * The contract makes errors a closed set precisely so the UI can offer a
 * *correct* action for each rather than a generic "something went wrong"
 * (docs/ffi-contract.md, design rule 3). Retrying a `Denied` is pointless and
 * teaches users to mash buttons; retrying a `Transport` is exactly right.
 */
data class ErrorPresentation(
    val title: String,
    val detail: String,
    val actionLabel: String?,
    val action: ErrorAction,
)

enum class ErrorAction { Retry, GoPair, None }

fun Throwable.toPresentation(): ErrorPresentation = when (this) {
    is GonomadError.Denied -> ErrorPresentation(
        title = "Not permitted",
        detail = "This device was not granted `$capability`. Grant it on the laptop " +
            "under Devices, then try again. Secret paths also need a fresh biometric.",
        actionLabel = null,
        action = ErrorAction.None,
    )

    is GonomadError.NotFound -> ErrorPresentation(
        title = "No longer there",
        detail = "The daemon could not find that path. It may have been moved or " +
            "deleted since this listing was fetched.",
        actionLabel = "Refresh",
        action = ErrorAction.Retry,
    )

    is GonomadError.RateLimited -> ErrorPresentation(
        title = "Rate limited",
        detail = "The daemon is throttling this device. Try again in about " +
            "${(retryAfterMs.toLong() / 1000).coerceAtLeast(1)} s.",
        actionLabel = "Try again",
        action = ErrorAction.Retry,
    )

    is GonomadError.Unsupported -> ErrorPresentation(
        title = "Can't open this",
        detail = when (feature) {
            "binary file" -> "This file is not UTF-8 text. The viewer refuses binary " +
                "content rather than showing you mojibake."
            "directory read" -> "That is a directory, not a file."
            else -> "The daemon does not support `$feature` in this build."
        },
        actionLabel = null,
        action = ErrorAction.None,
    )

    is GonomadError.Transport -> ErrorPresentation(
        title = "Can't reach the daemon",
        detail = "$detail. Check the laptop is awake and on the same network — " +
            "nothing is lost, the daemon keeps your terminals running.",
        actionLabel = "Reconnect",
        action = ErrorAction.Retry,
    )

    is GonomadError.Protocol -> ErrorPresentation(
        title = "Protocol error",
        detail = "$detail. This usually means the app and the daemon are different " +
            "versions.",
        actionLabel = "Try again",
        action = ErrorAction.Retry,
    )

    is GonomadError.NotPaired -> ErrorPresentation(
        title = "Not paired",
        detail = "This phone is not paired with a machine yet.",
        actionLabel = "Pair a machine",
        action = ErrorAction.GoPair,
    )

    else -> ErrorPresentation(
        title = "Something went wrong",
        detail = message ?: this::class.simpleName ?: "Unknown failure",
        actionLabel = "Try again",
        action = ErrorAction.Retry,
    )
}
