package dev.gonomad.app.ui.common

import dev.gonomad.ffi.GonomadException

/**
 * One rendering per member of the closed error enum.
 *
 * The core makes errors a closed set precisely so the UI can offer a *correct*
 * action for each rather than a generic "something went wrong" (§11.2). Retrying
 * a `Denied` is pointless and teaches users to mash buttons; retrying a
 * `Transport` is exactly right.
 */
data class ErrorPresentation(
    val title: String,
    val detail: String,
    val actionLabel: String?,
    val action: ErrorAction,
)

enum class ErrorAction { Retry, GoPair, None }

/**
 * Where the failure happened.
 *
 * Two variants read differently during pairing, and getting them wrong is not
 * cosmetic. With `IKpsk2` the machine finishes its half of the handshake even
 * when the pairing code was wrong, so a mistyped code surfaces on the phone as
 * `Transport` — the authenticated `sys.register` never round-trips (§19 R24).
 * Rendering that as "check your network" sends the user to reboot their router
 * over a typo.
 */
enum class ErrorSite { General, Pairing }

fun Throwable.toPresentation(site: ErrorSite = ErrorSite.General): ErrorPresentation =
    when (this) {
        // Subclasses of the generated sealed class are `class`, not `object`, so
        // every branch here is an `is` check — `==` would never match.
        is GonomadException.Denied -> ErrorPresentation(
            title = "Not permitted",
            detail = "This device does not hold `$capability`. Grant it on the machine " +
                "under Devices, then try again. Secret paths need a fresh biometric too.",
            actionLabel = null,
            action = ErrorAction.None,
        )

        is GonomadException.NotFound -> ErrorPresentation(
            title = "No longer there",
            detail = "Your machine has nothing at that path, or it sits outside the " +
                "workspace roots. It may have moved since this listing was fetched.",
            actionLabel = "Refresh",
            action = ErrorAction.Retry,
        )

        is GonomadException.RateLimited -> ErrorPresentation(
            title = "Slow down",
            detail = "Your machine is throttling this device. Try again in about " +
                "${(retryAfterMs.toLong() / 1_000).coerceAtLeast(1)} s.",
            actionLabel = "Try again",
            action = ErrorAction.Retry,
        )

        // Version skew, always: the FFI maps "daemon too old", "app too old", and
        // an unknown method here. It is never a property of the file you opened.
        is GonomadException.Unsupported -> ErrorPresentation(
            title = "Versions don't match",
            detail = "Your machine's GoNomad does not support `$feature`. Update the " +
                "machine and the app to the same version — the protocol is negotiated " +
                "once at connect, so a mismatch will not resolve itself.",
            actionLabel = null,
            action = ErrorAction.None,
        )

        // Reachability, at both sites. This used to claim "that code didn't
        // match" while pairing, which was wrong and expensively so: a phone on
        // mobile data and a genuinely mistyped code produced the same sentence,
        // and it named the one cause the user could not do anything about. A
        // rejected code is now its own variant below.
        is GonomadException.Transport -> when (site) {
            ErrorSite.Pairing -> ErrorPresentation(
                title = "Couldn't reach your machine",
                detail = "$detail The code itself was never checked — nothing answered. " +
                    "Check that `gonomad pair` is still running and that the machine is " +
                    "awake. Different networks are fine; it does not need to be the same " +
                    "Wi-Fi.",
                actionLabel = "Try again",
                action = ErrorAction.Retry,
            )

            ErrorSite.General -> ErrorPresentation(
                title = "Can't reach your machine",
                detail = "$detail Nothing is lost — your terminals keep running there.",
                actionLabel = "Reconnect",
                action = ErrorAction.Retry,
            )
        }

        // The machine answered and turned the code down. The only branch where
        // rescanning is the right advice.
        is GonomadException.PairingRejected -> ErrorPresentation(
            title = "That code didn't match",
            detail = "Your machine answered and rejected this code, so it was wrong or the " +
                "120-second window had closed. Run `gonomad pair` again and scan the new QR.",
            actionLabel = "Try again",
            action = ErrorAction.Retry,
        )

        is GonomadException.Protocol -> when (site) {
            ErrorSite.Pairing -> ErrorPresentation(
                title = "That isn't a GoNomad code",
                detail = "$detail Run `gonomad pair` on the machine and scan the QR it " +
                    "prints; the window is 120 seconds and single use.",
                actionLabel = "Try again",
                action = ErrorAction.Retry,
            )

            ErrorSite.General -> ErrorPresentation(
                title = "Your machine refused that",
                detail = detail,
                actionLabel = "Try again",
                action = ErrorAction.Retry,
            )
        }

        is GonomadException.NotPaired -> ErrorPresentation(
            title = "Not paired",
            detail = "This phone is not paired with a machine yet, so there is nothing to " +
                "connect to.",
            actionLabel = "Pair a machine",
            action = ErrorAction.GoPair,
        )

        // Not from the core: a cancelled coroutine, or a bug. Say so plainly
        // rather than dressing it up as a protocol failure.
        else -> ErrorPresentation(
            title = "Something went wrong",
            detail = message ?: this::class.simpleName ?: "Unknown failure",
            actionLabel = "Try again",
            action = ErrorAction.Retry,
        )
    }
