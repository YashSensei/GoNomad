package dev.gonomad.app.feature.pair

import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * CameraX preview with an ML Kit QR analyser bound to it.
 *
 * Analysis runs on its own single-thread executor with
 * `STRATEGY_KEEP_ONLY_LATEST`, so a slow decode drops frames rather than
 * queueing them and lagging the viewfinder.
 */
@Composable
fun QrScannerPreview(
    onDetected: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    // The pairing window is single use, so the first decode wins and later
    // frames are dropped — a steady hand otherwise fires this thirty times a
    // second and starts thirty handshakes.
    val consumed = remember { AtomicBoolean(false) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val boundProvider = remember { AtomicReference<ProcessCameraProvider?>(null) }

    DisposableEffect(Unit) {
        onDispose {
            // Never block the main thread waiting on the provider future here;
            // if it never resolved there is nothing bound to release.
            boundProvider.getAndSet(null)?.unbindAll()
            executor.shutdown()
        }
    }

    Box(modifier = modifier) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                val previewView = PreviewView(ctx).apply {
                    scaleType = PreviewView.ScaleType.FILL_CENTER
                    implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                }

                val providerFuture = ProcessCameraProvider.getInstance(ctx)
                providerFuture.addListener(
                    {
                        val provider = runCatching { providerFuture.get() }.getOrNull()
                            ?: return@addListener

                        val preview = Preview.Builder().build()
                        preview.setSurfaceProvider(previewView.surfaceProvider)

                        val scanner = BarcodeScanning.getClient(
                            BarcodeScannerOptions.Builder()
                                .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                                .build(),
                        )

                        val analysis = ImageAnalysis.Builder()
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()
                        analysis.setAnalyzer(executor, QrAnalyzer(scanner, consumed, onDetected))

                        runCatching {
                            provider.unbindAll()
                            provider.bindToLifecycle(
                                lifecycleOwner,
                                CameraSelector.DEFAULT_BACK_CAMERA,
                                preview,
                                analysis,
                            )
                            boundProvider.set(provider)
                        }
                    },
                    ContextCompat.getMainExecutor(ctx),
                )

                previewView
            },
        )

        ViewfinderBrackets(modifier = Modifier.fillMaxSize())
    }
}

private class QrAnalyzer(
    private val scanner: BarcodeScanner,
    private val consumed: AtomicBoolean,
    private val onDetected: (String) -> Unit,
) : ImageAnalysis.Analyzer {

    @OptIn(ExperimentalGetImage::class)
    override fun analyze(image: ImageProxy) {
        val media = image.image
        if (media == null || consumed.get()) {
            image.close()
            return
        }
        val input = InputImage.fromMediaImage(media, image.imageInfo.rotationDegrees)
        scanner.process(input)
            .addOnSuccessListener { codes ->
                val value = codes.firstNotNullOfOrNull { it.rawValue }
                if (value != null && consumed.compareAndSet(false, true)) {
                    onDetected(value)
                }
            }
            .addOnCompleteListener { image.close() }
    }
}

/**
 * Corner brackets rather than a dimming mask: four marks say "aim here"
 * without darkening the thing the user is trying to see.
 */
@Composable
private fun ViewfinderBrackets(
    modifier: Modifier = Modifier,
    colour: Color = Color(0xFF5EC8C0),
) {
    Canvas(modifier = modifier) {
        val side = minOf(size.width, size.height) * 0.66f
        val left = (size.width - side) / 2f
        val top = (size.height - side) / 2f
        val right = left + side
        val bottom = top + side
        val arm = side * 0.16f
        val w = 3.dp.toPx()
        val cap = StrokeCap.Round

        fun mark(from: Offset, to: Offset) = drawLine(colour, from, to, w, cap)

        mark(Offset(left, top + arm), Offset(left, top))
        mark(Offset(left, top), Offset(left + arm, top))

        mark(Offset(right - arm, top), Offset(right, top))
        mark(Offset(right, top), Offset(right, top + arm))

        mark(Offset(left, bottom - arm), Offset(left, bottom))
        mark(Offset(left, bottom), Offset(left + arm, bottom))

        mark(Offset(right - arm, bottom), Offset(right, bottom))
        mark(Offset(right, bottom - arm), Offset(right, bottom))
    }
}
