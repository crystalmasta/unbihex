#!/bin/sh
# Builds libunbihex.a for the Packet Tunnel extension (run on a Mac from the repo root).
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
set -e
cargo build --release -p unbihex-ffi --target aarch64-apple-ios
cargo build --release -p unbihex-ffi --target aarch64-apple-ios-sim
mkdir -p ios/PacketTunnel/lib
cp target/aarch64-apple-ios/release/libunbihex.a ios/PacketTunnel/lib/libunbihex-ios.a
cp target/aarch64-apple-ios-sim/release/libunbihex.a ios/PacketTunnel/lib/libunbihex-sim.a
cp crates/unbihex-ffi/include/unbihex.h ios/PacketTunnel/
echo "Готово: ios/PacketTunnel/lib/*.a и unbihex.h"
