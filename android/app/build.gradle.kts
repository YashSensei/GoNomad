import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Release signing credentials, loaded from a git-ignored file.
//
// Absent on a fresh clone and in CI, which is deliberate: the build still works,
// it just cannot produce a signed release. Failing the whole build because a
// contributor has no signing key would be hostile, so `assembleRelease` simply
// falls back to unsigned and says so.
val keystoreProps: Properties? =
    rootProject.file("keystore.properties").takeIf { it.exists() }?.let { file ->
        Properties().also { props -> file.inputStream().use(props::load) }
    }

android {
    namespace = "dev.gonomad.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.gonomad.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-alpha01"

        // arm64-v8a only for MVP (ARCHITECTURE.md 6.4). armeabi-v7a and x86_64
        // land at M6; adding them now would triple the Rust build for ABIs
        // nobody is testing on.
        ndk { abiFilters += "arm64-v8a" }
        vectorDrawables.useSupportLibrary = true
    }

    sourceSets {
        getByName("main") {
            // The Rust core's compiled library and its generated Kotlin
            // bindings. Both are build outputs, not sources, so they are
            // git-ignored and produced by `cargoNdkBuild` below.
            jniLibs.srcDir(layout.buildDirectory.dir("rustJniLibs"))
            java.srcDir(layout.buildDirectory.dir("generated/uniffi"))
        }
    }

    signingConfigs {
        keystoreProps?.let { props ->
            create("release") {
                storeFile = rootProject.file(props.getProperty("storeFile"))
                storePassword = props.getProperty("storePassword")
                keyAlias = props.getProperty("keyAlias")
                keyPassword = props.getProperty("keyPassword")
                // v1 as well as v2/v3: v1 is what lets the APK install by tapping
                // it in a file manager on older Android, which is exactly how a
                // sideloaded build gets installed.
                enableV1Signing = true
                enableV2Signing = true
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf(
            "-opt-in=kotlin.ExperimentalUnsignedTypes",
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=androidx.compose.foundation.ExperimentalFoundationApi",
        )
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    lint {
        warningsAsErrors = false
        abortOnError = false
    }
}

// ---------------------------------------------------------------------------
// The Rust core.
//
// Two outputs, both produced from `crates/gonomad-ffi`:
//
//   1. libgonomad_ffi.so   — cross-compiled with cargo-ndk into build/rustJniLibs
//   2. gonomad_ffi.kt      — UniFFI bindings into build/generated/uniffi
//
// Both are generated rather than committed, so they cannot drift from the Rust
// source. That does mean building the app requires the Rust toolchain and the
// NDK; for a project whose core *is* Rust that is the right trade, and the task
// fails with an actionable message rather than a linker error if either is
// missing.
//
// Bindings are generated from the HOST library, not the Android one, because the
// release profile sets `strip = "symbols"` and stripping removes the metadata
// symbols UniFFI reads. The generated Kotlin is architecture-independent, so the
// host library is the correct source either way.
// ---------------------------------------------------------------------------

val rustRoot: File = rootProject.projectDir.parentFile
val cargoBin: String = System.getenv("USERPROFILE")?.let { "$it\\.cargo\\bin\\cargo" }
    ?: System.getenv("HOME")?.let { "$it/.cargo/bin/cargo" }
    ?: "cargo"

// Resolved at CONFIGURATION time, deliberately. Doing this inside a task action
// captures script-level objects, which the configuration cache refuses to
// serialize — the failure message points at Exec rather than at the closure, so
// it is worth stating why the value is hoisted.
val ndkPath: String? = System.getenv("ANDROID_NDK_HOME")
    ?: android.sdkDirectory.resolve("ndk").takeIf { it.isDirectory }
        ?.listFiles()
        ?.filter { it.isDirectory }
        ?.maxByOrNull { it.name }
        ?.absolutePath

// Every Rust file the two tasks below depend on.
//
// Declaring these is not optional hygiene: without them Gradle sees a task with
// declared outputs and no declared inputs, marks it UP-TO-DATE forever, and
// happily packages a stale .so. The app then calls a function the library does
// not contain, which surfaces at runtime as a native crash rather than a build
// error. Verified by editing a Rust file and confirming the task reruns.
val rustInputs: FileTree = fileTree(rustRoot) {
    include("crates/**/*.rs")
    include("crates/**/Cargo.toml")
    include("Cargo.toml")
    include("Cargo.lock")
    include("rust-toolchain.toml")
    exclude("**/target/**")
}

val cargoNdkBuild by tasks.registering(Exec::class) {
    group = "rust"
    description = "Cross-compiles gonomad-ffi for arm64-v8a into build/rustJniLibs."

    val outDir = layout.buildDirectory.dir("rustJniLibs").get().asFile
    inputs.files(rustInputs).withPropertyName("rustSources")
    outputs.dir(outDir)

    // Fail at configuration with something actionable rather than letting cargo
    // emit a linker error nobody can act on.
    if (ndkPath == null) {
        throw GradleException(
            "No Android NDK found. Install one via the SDK Manager or set " +
                "ANDROID_NDK_HOME. GoNomad's core is Rust and must be " +
                "cross-compiled; there is no pure-Kotlin fallback.",
        )
    }
    environment("ANDROID_NDK_HOME", ndkPath)

    workingDir = rustRoot
    // Release, because it is stripped and is what a shipped build should carry.
    // Note that stripping is also why bindings come from the host library.
    commandLine(
        cargoBin, "ndk",
        "-t", "arm64-v8a",
        "-o", outDir.absolutePath,
        "build", "--release", "-p", "gonomad-ffi",
    )
}

// The host cdylib UniFFI reads metadata from. Also resolved at configuration
// time, for the same configuration-cache reason as `ndkPath`.
val hostLibrary: String = run {
    val osName = System.getProperty("os.name")
    val name = when {
        osName.startsWith("Windows") -> "gonomad_ffi.dll"
        osName.contains("Mac") -> "libgonomad_ffi.dylib"
        else -> "libgonomad_ffi.so"
    }
    rustRoot.resolve("target/debug/$name").absolutePath
}

val uniffiBindings by tasks.registering(Exec::class) {
    group = "rust"
    description = "Generates Kotlin bindings for gonomad-ffi from the host library."

    val outDir = layout.buildDirectory.dir("generated/uniffi").get().asFile
    inputs.files(rustInputs).withPropertyName("rustSources")
    outputs.dir(outDir)

    workingDir = rustRoot
    commandLine(
        cargoBin, "run", "--quiet",
        "-p", "gonomad-ffi", "--bin", "uniffi-bindgen", "--",
        "generate",
        "--library", hostLibrary,
        "--language", "kotlin",
        "--out-dir", outDir.absolutePath,
    )
}

val cargoHostBuild by tasks.registering(Exec::class) {
    group = "rust"
    description = "Builds the host gonomad-ffi library, whose symbols UniFFI reads."
    // Same reasoning as cargoNdkBuild: without declared inputs this would go
    // UP-TO-DATE and uniffiBindings would regenerate from a stale host library,
    // producing Kotlin that does not match the .so actually shipped.
    inputs.files(rustInputs).withPropertyName("rustSources")
    outputs.file(hostLibrary)
    workingDir = rustRoot
    commandLine(cargoBin, "build", "--quiet", "-p", "gonomad-ffi")
}

uniffiBindings { dependsOn(cargoHostBuild) }

// Both outputs must exist before Kotlin compiles or the APK is packaged.
tasks.matching { it.name.startsWith("compile") && it.name.contains("Kotlin") }
    .configureEach { dependsOn(uniffiBindings) }
tasks.matching { it.name.startsWith("merge") && it.name.contains("JniLibFolders") }
    .configureEach { dependsOn(cargoNdkBuild) }
tasks.matching { it.name.startsWith("assemble") }
    .configureEach { dependsOn(cargoNdkBuild, uniffiBindings) }

dependencies {
    // UniFFI's Kotlin backend calls the .so through JNA.
    implementation(variantOf(libs.jna) { artifactType("aar") })

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.navigation.compose)

    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.mlkit.barcode.scanning)
}
