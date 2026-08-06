# UniFFI generates JNA-backed bindings; JNA reflects over these structures, so
# they must survive R8 once the real gonomad-ffi crate is wired in.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class dev.gonomad.ffi.** { *; }

# kotlinx.serialization keeps generated serializers off the reflection path.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class dev.gonomad.app.** {
    *** Companion;
}
