package dev.gonomad.app.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.gonomad.ffi.ConnState
import dev.gonomad.ffi.Status
import dev.gonomad.app.ui.theme.Space
import dev.gonomad.app.ui.theme.semantic

/**
 * Connection tier, always visible (ARCHITECTURE.md 23.1, principle 4).
 *
 * The dot is never the only signal: every state also carries a word, because
 * about 1 in 12 men cannot reliably separate the muted green from the muted
 * amber in this palette (ARCHITECTURE.md 23.4).
 */
@Composable
fun ConnectionChip(
    status: Status,
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
) {
    val semantic = MaterialTheme.semantic
    val transport = status.transport
    val (label, dot, container) = when (status.state) {
        // A relayed session is not an error, but it is worth noticing: it means
        // hole punching failed and traffic is taking a longer path.
        ConnState.CONNECTED -> when (transport) {
            "LAN" -> Triple("LAN", semantic.ok, semantic.okContainer)
            null -> Triple("Connected", semantic.ok, semantic.okContainer)
            else -> Triple(transport, semantic.warn, semantic.warnContainer)
        }
        ConnState.CONNECTING -> Triple("Connecting", semantic.warn, semantic.warnContainer)
        ConnState.DISCONNECTED -> Triple("Offline", semantic.danger, semantic.dangerContainer)
        ConnState.UNPAIRED -> Triple("Not paired", semantic.textLow, MaterialTheme.colorScheme.surfaceContainerHigh)
        ConnState.REVOKED -> Triple("Revoked", semantic.danger, semantic.dangerContainer)
    }

    val rtt = status.rttMs
    val suffix = when {
        status.state == ConnState.CONNECTED && rtt != null -> "  ·  $rtt ms"
        else -> ""
    }

    val animatedContainer by animateColorAsState(container, label = "chipContainer")

    var chip = modifier
        .clip(RoundedCornerShape(999.dp))
        .background(animatedContainer)
    if (onClick != null) chip = chip.clickable(onClick = onClick)

    Row(
        modifier = chip
            .defaultMinSize(minHeight = 32.dp)
            .padding(horizontal = Space.m, vertical = Space.s)
            .clearAndSetSemantics {
                contentDescription = buildString {
                    append("Connection: ")
                    append(label)
                    if (rtt != null && status.state == ConnState.CONNECTED) {
                        append(", round trip $rtt milliseconds")
                    }
                }
            },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        StateDot(colour = dot, pulsing = status.state == ConnState.CONNECTING)
        Text(
            text = label + suffix,
            style = MaterialTheme.typography.labelMedium,
            color = dot,
        )
    }
}

/** A small filled dot; pulses while a state is in flight. */
@Composable
fun StateDot(colour: Color, pulsing: Boolean = false, size: Dp = 8.dp) {
    val alpha = if (pulsing) {
        val transition = rememberInfiniteTransition(label = "dotPulse")
        val v by transition.animateFloat(
            initialValue = 0.35f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(750, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse,
            ),
            label = "dotAlpha",
        )
        v
    } else {
        1f
    }

    Box(
        modifier = Modifier
            .size(size)
            .alpha(alpha)
            .clip(CircleShape)
            .background(colour),
    )
}
