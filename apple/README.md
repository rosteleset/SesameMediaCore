# SesameMediaCore for Apple platforms

`SesameMediaCore.xcframework` exposes the shared Rust CBCS/CMAF implementation
to Swift and Objective-C through a small C ABI. The framework contains slices
for iOS device, iOS Simulator, and macOS.

## Build

Install the Rust targets once:

```bash
rustup target add \
  aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
  aarch64-apple-darwin x86_64-apple-darwin
```

Then rebuild the checked-in framework:

```bash
./apple/scripts/build-xcframework.sh
```

The script builds `sesame_cmaf_cbcs` as static libraries, combines universal
Simulator and macOS slices, and recreates
`apple/SesameMediaCore.xcframework` through `xcodebuild`.

## ABI contract

The public declarations are in `apple/include/SesameMediaCore.h`.

- `sesame_cmaf_cbcs_clear_initialization` converts an encrypted initialization
  section to clear CMAF and returns an opaque immutable track context.
- `sesame_cmaf_cbcs_clear_fragment` decrypts one fragment with caller-provided
  KID/CEK records and can normalize its playback timeline.
- `sesame_cmaf_normalize_clear_initialization` adds the explicit color metadata
  required by AVFoundation when it is missing.
- Every returned `SesameMediaBuffer` must be released exactly once with
  `sesame_media_buffer_free`.
- Every context must be released exactly once with
  `sesame_cmaf_cbcs_context_free`.
- Callers must reject an unexpected `sesame_media_core_abi_version` before
  passing media data.

The context is read-only after creation and may be shared by concurrent
fragment requests. Content keys are copied into zeroizing Rust values for the
duration of one decrypt call and are never retained by the context.

## Platform bindings

iOS and macOS import the XCFramework directly from Swift Package Manager. A
future Android AAR should call the same Rust functions through a thin JNI
adapter; CBCS parsing and cryptography must remain in this crate rather than be
duplicated in Kotlin.
