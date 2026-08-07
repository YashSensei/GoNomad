# UniFFI generates JNA-backed bindings, and JNA resolves everything it touches
# reflectively. R8 cannot see any of those edges, so all of it has to be kept or
# a minified release build fails at the first FFI call rather than at build time.

# JNA is built for desktop JVMs and references java.awt for its window/component
# helpers. Those classes do not exist on Android at all, so R8 reports them as
# missing and fails the build. The referencing code (com.sun.jna.Native$AWT) is
# unreachable here — nothing in GoNomad asks JNA for a window handle — so telling
# R8 not to warn is correct rather than a workaround.
#
# Found by actually building a release APK. The debug build never runs R8, so this
# was invisible until the first `assembleRelease`.
-dontwarn java.awt.**
-dontwarn javax.swing.**

# JNA itself: Structure subclasses are read field-by-field by name, Callback
# implementations are invoked from native code, and Library interfaces are
# implemented at runtime by a proxy.
-keep class com.sun.jna.** { *; }
-keep interface com.sun.jna.** { *; }
-keep class * implements com.sun.jna.Library { *; }
-keep class * implements com.sun.jna.Callback { *; }
-keep class * extends com.sun.jna.Structure { *; }
-keepclassmembers class * extends com.sun.jna.Structure {
    <fields>;
}

# The generated bindings. `@JvmField` members of the vtable structures, the
# callback singletons Rust holds handles to, and the FfiConverter objects are all
# reached only from native code or by reflection.
-keep class dev.gonomad.ffi.** { *; }
-keepclassmembers class dev.gonomad.ffi.** {
    <fields>;
    <methods>;
}

# kotlinx.serialization keeps generated serializers off the reflection path.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class dev.gonomad.app.** {
    *** Companion;
}
