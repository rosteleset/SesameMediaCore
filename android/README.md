# SesameMediaCore for Android

The Android artifact exposes the shared CBCS/CMAF implementation through a thin JNI layer.
The media parser, timeline repair, and AES-CBCS work stay in Rust; Kotlin owns Android lifecycle,
Keystore access, HLS metadata, and Media3 integration.

Build the native libraries with:

```sh
ANDROID_NDK_HOME=/path/to/android-ndk \
  ./android/scripts/build-jni.sh
```

The script writes `libsesame_media_core_jni.so` for `arm64-v8a`, `armeabi-v7a`, and `x86_64`
under `android/jniLibs/`. That directory is copied into the SesameDVR Android Kit AAR.

The JNI API is intentionally session-based:

1. `nativeCreateSession()` parses a protected initialization segment.
2. `nativeClearInitialization()` returns its clear CMAF equivalent.
3. `nativeKeyIds()` returns the KIDs required by the initialization segment.
4. `nativeClearFragment()` decrypts a media fragment with caller-provided KID/CEK records.
5. `nativeDestroySession()` releases native state.

Session identifiers are validated through a process-local registry, so a stale Java handle cannot
be dereferenced as a native pointer.
