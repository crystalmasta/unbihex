#!/bin/sh
# Builds libunbihex.a for the Packet Tunnel extension (run on a Mac from unbihex-client/).
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   sh ios/PacketTunnel/build-ffi.sh          # device and simulator
#   sh ios/PacketTunnel/build-ffi.sh ios      # device only (CI)
set -e
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
# C code (ring) must target the same iOS as the extension (bundle.iOS.minimumSystemVersion).
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
KINDS="${*:-ios sim}"
mkdir -p ios/PacketTunnel/lib
for kind in $KINDS; do
    case "$kind" in
        ios) triple=aarch64-apple-ios ;;
        sim) triple=aarch64-apple-ios-sim ;;
        *) echo "Неизвестная цель: $kind (ios или sim)" >&2; exit 1 ;;
    esac
    cargo build --release --locked -p unbihex-ffi --target "$triple"
    cp "$TARGET_DIR/$triple/release/libunbihex.a" "ios/PacketTunnel/lib/libunbihex-$kind.a"
done
cp crates/unbihex-ffi/include/unbihex.h ios/PacketTunnel/
echo "Готово: ios/PacketTunnel/lib/*.a и unbihex.h"
