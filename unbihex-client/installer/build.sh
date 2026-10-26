#!/bin/sh
# Собирает установщик Windows (нужен NSIS 3; путь к makensis можно задать в MAKENSIS).
# Сначала (статический CRT, чтобы не требовать Visual C++ Redistributable):
#   RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -p unbihex-client --target x86_64-pc-windows-msvc
set -e
cd "$(dirname "$0")"
R=../target/x86_64-pc-windows-msvc/release
MAKENSIS=${MAKENSIS:-makensis}
cp "$R/unbihex-client.exe" Unbihex.exe
cp ../app/src-tauri/resources/wintun.dll ../app/src-tauri/resources/wintun-LICENSE.txt .
cp ../app/src-tauri/icons/icon.ico .
[ -f MicrosoftEdgeWebview2Setup.exe ] || curl -sSL -o MicrosoftEdgeWebview2Setup.exe "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
# The script is UTF-8 without a BOM; on Windows makensis would read it as the ANSI code page.
"$MAKENSIS" -V2 -INPUTCHARSET UTF8 unbihex.nsi
