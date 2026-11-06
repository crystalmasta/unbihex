#!/bin/bash
# By akurach (github.com/akurach), PR #50.
# An unofficial macOS (Apple Silicon) build: ad-hoc signed, not notarized.
set -euo pipefail

# Build in an isolated target directory and never replace an existing delivery.
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLIENT="$ROOT/unbihex-client"
OUT="$CLIENT/dist/macos-arm64"
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo 'An Apple Silicon Mac is required.' >&2; exit 1; }
[[ ! -e "$OUT" ]] || { echo "Output already exists: $OUT (move it before rebuilding)" >&2; exit 1; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/unbihex-macos.XXXXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export CARGO_TARGET_DIR="$WORK/target"
export MACOSX_DEPLOYMENT_TARGET=11.0
VERSION="$(cd "$CLIENT" && cargo metadata --locked --no-deps --format-version 1 | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const p=JSON.parse(s).packages.find(p=>p.name==="unbihex-client");if(!p)process.exit(1);process.stdout.write(p.version)})')"
CONFIG_VERSION="$(node -p 'require(process.argv[1]).version' "$CLIENT/app/src-tauri/tauri.conf.json")"
[[ "$VERSION" == "$CONFIG_VERSION" && "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] || { echo 'Manifest and Tauri versions differ or are invalid.' >&2; exit 1; }
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
TREE_STATE=clean
if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]]; then TREE_STATE=dirty; fi
printf '%s\n' '{"bundle":{"macOS":{"minimumSystemVersion":"11.0"}}}' > "$WORK/tauri-macos.json"
# Keep the CLI in step with the `tauri` crate in unbihex-client/Cargo.lock.
npm install --prefix "$WORK/cli" --no-save --no-package-lock --ignore-scripts @tauri-apps/cli@2.11.4
cd "$CLIENT"
cargo build --release --locked -p unbihex-client --target aarch64-apple-darwin
cd "$CLIENT/app/src-tauri"
"$WORK/cli/node_modules/.bin/tauri" bundle --target aarch64-apple-darwin --bundles app --config "$WORK/tauri-macos.json" --no-sign --ci
APP="$CARGO_TARGET_DIR/aarch64-apple-darwin/release/bundle/macos/Unbihex.app"
[[ -d "$APP" ]] || { echo 'Tauri did not produce Unbihex.app.' >&2; exit 1; }
mkdir -p "$APP/Contents/Resources"
cp "$ROOT/LICENSE" "$APP/Contents/Resources/LICENSE"
cp "$ROOT/LICENSE.ru.md" "$APP/Contents/Resources/LICENSE.ru.md"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
BIN="$APP/Contents/MacOS/unbihex-client"
[[ "$(lipo -archs "$BIN")" == arm64 ]] || { echo 'Unexpected executable architecture.' >&2; exit 1; }
MINOS="$(xcrun vtool -show-build "$BIN" | awk '$1 == "minos" {print $2; exit}')"
PLIST_MIN="$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$APP/Contents/Info.plist")"
[[ "$MINOS" == 11.0 || "$MINOS" == 11.0.0 ]] && [[ "$PLIST_MIN" == 11.0 || "$PLIST_MIN" == 11.0.0 ]] || { echo "Unexpected minimum OS: binary=$MINOS plist=$PLIST_MIN" >&2; exit 1; }
mkdir -p "$WORK/delivery"
ZIP="Unbihex-$VERSION-macos-arm64.zip"
ditto -c -k --keepParent "$APP" "$WORK/delivery/$ZIP"
cp "$ROOT/LICENSE" "$ROOT/LICENSE.ru.md" "$WORK/delivery/"
(cd "$WORK/delivery" && shasum -a 256 "$ZIP" > SHA256SUMS.txt)
cat > "$WORK/delivery/BUILD.md" <<BUILD
# Build information

- Source version: $VERSION
- Source commit: $COMMIT; working tree: $TREE_STATE
- Target: aarch64-apple-darwin; deployment target: $MACOSX_DEPLOYMENT_TARGET
- Binary minimum macOS: $MINOS; Info.plist minimum macOS: $PLIST_MIN
- Rust: $(rustc --version)
- Cargo: $(cargo --version)
- Node: $(node --version); npm: $(npm --version)
- Tauri CLI: $("$WORK/cli/node_modules/.bin/tauri" --version)
- Xcode: $(xcodebuild -version | tr '\n' ' ')
- Signature: ad-hoc; no Developer ID signature or Apple notarization. Gatekeeper may block the app.
- Intel, older macOS versions, and VPN functionality have not been tested by this build process.
- Builds are not guaranteed to be bit-for-bit reproducible.
BUILD
mkdir -p "$(dirname "$OUT")"
# mkdir prevents overwriting an output created while the build was running.
mkdir "$OUT"
cp "$WORK/delivery/"* "$OUT/"
printf 'Artifacts: %s\n' "$OUT"
