#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/target/apple-xcframework"
OUTPUT="${ROOT_DIR}/apple/SesameMediaCore.xcframework"
HEADER="${ROOT_DIR}/apple/include/SesameMediaCore.h"
CRATE="sesame_cmaf_cbcs"
LIBRARY="libsesame_cmaf_cbcs.a"

rm -rf "${BUILD_DIR}" "${OUTPUT}"
mkdir -p "${BUILD_DIR}"

for target in \
    aarch64-apple-ios \
    aarch64-apple-ios-sim \
    x86_64-apple-ios \
    aarch64-apple-darwin \
    x86_64-apple-darwin; do
    cargo build --manifest-path "${ROOT_DIR}/Cargo.toml" \
        --package "${CRATE}" \
        --release \
        --target "${target}"
done

mkdir -p "${BUILD_DIR}/simulator"
lipo -create \
    "${ROOT_DIR}/target/aarch64-apple-ios-sim/release/${LIBRARY}" \
    "${ROOT_DIR}/target/x86_64-apple-ios/release/${LIBRARY}" \
    -output "${BUILD_DIR}/simulator/${LIBRARY}"

mkdir -p "${BUILD_DIR}/macos"
lipo -create \
    "${ROOT_DIR}/target/aarch64-apple-darwin/release/${LIBRARY}" \
    "${ROOT_DIR}/target/x86_64-apple-darwin/release/${LIBRARY}" \
    -output "${BUILD_DIR}/macos/${LIBRARY}"

make_framework() {
    local library="$1"
    local destination="$2"
    local platform="$3"
    local platform_variant="${4:-}"

    local framework="${destination}/SesameMediaCore.framework"
    mkdir -p "${framework}/Headers" "${framework}/Modules"
    cp "${library}" "${framework}/SesameMediaCore"
    cp "${HEADER}" "${framework}/Headers/SesameMediaCore.h"
    cat > "${framework}/Modules/module.modulemap" <<'MODULEMAP'
framework module SesameMediaCore {
    umbrella header "SesameMediaCore.h"
    export *
}
MODULEMAP

    local variant_xml=""
    if [[ -n "${platform_variant}" ]]; then
        variant_xml="<key>DTPlatformVariant</key><string>${platform_variant}</string>"
    fi
    cat > "${framework}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleExecutable</key><string>SesameMediaCore</string>
<key>CFBundleIdentifier</key><string>com.sesameware.SesameMediaCore</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>SesameMediaCore</string>
<key>CFBundlePackageType</key><string>FMWK</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>DTPlatformName</key><string>${platform}</string>
${variant_xml}
</dict></plist>
PLIST
}

make_framework \
    "${ROOT_DIR}/target/aarch64-apple-ios/release/${LIBRARY}" \
    "${BUILD_DIR}/device" \
    "iphoneos"
make_framework \
    "${BUILD_DIR}/simulator/${LIBRARY}" \
    "${BUILD_DIR}/simulator-framework" \
    "iphonesimulator" \
    "simulator"
make_framework \
    "${BUILD_DIR}/macos/${LIBRARY}" \
    "${BUILD_DIR}/macos-framework" \
    "macosx"

xcodebuild -create-xcframework \
    -framework "${BUILD_DIR}/device/SesameMediaCore.framework" \
    -framework "${BUILD_DIR}/simulator-framework/SesameMediaCore.framework" \
    -framework "${BUILD_DIR}/macos-framework/SesameMediaCore.framework" \
    -output "${OUTPUT}"

echo "Created ${OUTPUT}"
