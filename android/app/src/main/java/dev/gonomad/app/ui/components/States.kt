package dev.gonomad.app.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.gonomad.app.ui.theme.Space
import dev.gonomad.app.ui.theme.semantic

/**
 * A shimmering placeholder block.
 *
 * The sweep is low amplitude on purpose: two adjacent tonal steps, not a white
 * highlight. A bright shimmer on this palette looks like a rendering bug.
 */
@Composable
fun ShimmerBlock(
    width: Dp? = null,
    height: Dp = 14.dp,
    shape: Shape = RoundedCornerShape(6.dp),
    modifier: Modifier = Modifier,
) {
    val transition = rememberInfiniteTransition(label = "shimmer")
    val phase by transition.animateFloat(
        initialValue = -600f,
        targetValue = 900f,
        animationSpec = infiniteRepeatable(tween(1_500, easing = LinearEasing)),
        label = "shimmerPhase",
    )
    val low = MaterialTheme.colorScheme.surfaceContainerHigh
    val high = MaterialTheme.colorScheme.surfaceContainerHighest

    val sized = if (width != null) modifier.width(width) else modifier.fillMaxWidth()
    Box(
        modifier = sized
            .height(height)
            .clip(shape)
            .background(
                Brush.linearGradient(
                    colors = listOf(low, high, low),
                    start = Offset(phase, 0f),
                    end = Offset(phase + 320f, 0f),
                ),
            ),
    )
}

/** Skeleton for a list of file rows. Mirrors the real row's metrics. */
@Composable
fun FileListSkeleton(rows: Int = 9, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = Space.l),
        verticalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        repeat(rows) { i ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(Space.m),
            ) {
                // Staggered indents so the skeleton reads as a tree, not a table.
                if (i % 3 == 1) HSpace(Space.l)
                ShimmerBlock(width = 20.dp, height = 20.dp, shape = RoundedCornerShape(6.dp))
                ShimmerBlock(width = (110 + (i * 37) % 130).dp, height = 12.dp)
            }
        }
    }
}

/** Skeleton for the file viewer: a gutter plus ragged code lines. */
@Composable
fun CodeSkeleton(rows: Int = 16, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(Space.l),
        verticalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        repeat(rows) { i ->
            Row(
                horizontalArrangement = Arrangement.spacedBy(Space.m),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                ShimmerBlock(width = 18.dp, height = 10.dp)
                ShimmerBlock(width = (70 + (i * 53) % 200).dp, height = 10.dp)
            }
        }
    }
}

@Composable
fun EmptyState(
    icon: ImageVector,
    title: String,
    body: String,
    modifier: Modifier = Modifier,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = Space.xl, vertical = Space.xxl),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(56.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.surfaceContainerHigh),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null, // decorative; the title carries the meaning
                tint = MaterialTheme.semantic.textLow,
                modifier = Modifier.size(24.dp),
            )
        }
        VSpace(Space.l)
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.Center,
        )
        VSpace(Space.s)
        Text(
            text = body,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.semantic.textLow,
            textAlign = TextAlign.Center,
        )
        if (actionLabel != null && onAction != null) {
            VSpace(Space.s)
            TextButton(onClick = onAction, modifier = Modifier.heightIn(min = 48.dp)) {
                Text(actionLabel, style = MaterialTheme.typography.labelLarge)
            }
        }
    }
}

@Composable
fun ErrorState(
    title: String,
    body: String,
    modifier: Modifier = Modifier,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = Space.xl, vertical = Space.xxl),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(56.dp)
                .clip(CircleShape)
                .background(MaterialTheme.semantic.dangerContainer),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Rounded.ErrorOutline,
                contentDescription = null,
                tint = MaterialTheme.semantic.danger,
                modifier = Modifier.size(26.dp),
            )
        }
        VSpace(Space.l)
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.Center,
        )
        VSpace(Space.s)
        Text(
            text = body,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.semantic.textLow,
            textAlign = TextAlign.Center,
        )
        if (actionLabel != null && onAction != null) {
            VSpace(Space.s)
            TextButton(onClick = onAction, modifier = Modifier.heightIn(min = 48.dp)) {
                Text(actionLabel, style = MaterialTheme.typography.labelLarge)
            }
        }
    }
}
