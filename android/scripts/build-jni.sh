#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
api_level="${ANDROID_API_LEVEL:-26}"
profile="${PROFILE:-release}"
rust_toolchain="${RUST_TOOLCHAIN:-stable}"
rustc_bin="$(rustup which --toolchain "$rust_toolchain" rustc)"

if [[ -z "$ndk_root" || ! -d "$ndk_root/toolchains/llvm/prebuilt" ]]; then
  echo "ANDROID_NDK_HOME must point to an Android NDK installation" >&2
  exit 2
fi

host_tag="$(find "$ndk_root/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | head -1)"
toolchain="$ndk_root/toolchains/llvm/prebuilt/$host_tag/bin"
output="$root_dir/android/jniLibs"

build_target() {
  local rust_target="$1"
  local android_triple="$2"
  local abi="$3"
  local linker="$toolchain/${android_triple}${api_level}-clang"
  local cargo_linker_name
  cargo_linker_name="CARGO_TARGET_$(printf '%s' "$rust_target" | tr '[:lower:]-' '[:upper:]_')_LINKER"

  rustup target add --toolchain "$rust_toolchain" "$rust_target"
  env "$cargo_linker_name=$linker" RUSTC="$rustc_bin" \
    rustup run "$rust_toolchain" cargo build --manifest-path "$root_dir/Cargo.toml" \
      --package sesame_media_core_jni \
      --target "$rust_target" \
      --profile "$profile"

  mkdir -p "$output/$abi"
  cp "$root_dir/target/$rust_target/$profile/libsesame_media_core_jni.so" \
    "$output/$abi/libsesame_media_core_jni.so"
}

build_target aarch64-linux-android aarch64-linux-android arm64-v8a
build_target armv7-linux-androideabi armv7a-linux-androideabi armeabi-v7a
build_target x86_64-linux-android x86_64-linux-android x86_64

echo "Android JNI libraries written to $output"
