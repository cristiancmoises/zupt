#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build zupt as AppImage (portable single-file binary).
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-2.2.2}"
ARCH="${ARCH:-x86_64}"
NAME="zupt-$VERSION-$ARCH"
OUT="/tmp/${NAME}.AppDir"

rm -rf "$OUT"
mkdir -p "$OUT/usr/bin" "$OUT/usr/lib" "$OUT/usr/share/applications" "$OUT/usr/share/icons/hicolor/256x256/apps"

install -m 755 zupt "$OUT/usr/bin/"
install -m 644 vendor/zuptsdk/libzuptsdk.so.2.0.0 "$OUT/usr/lib/"
ln -sf libzuptsdk.so.2.0.0 "$OUT/usr/lib/libzuptsdk.so.2"
ln -sf libzuptsdk.so.2 "$OUT/usr/lib/libzuptsdk.so"

cat > "$OUT/AppRun" <<'APPRUN'
#!/bin/bash
HERE="$(dirname "$(readlink -f "${0}")")"
export LD_LIBRARY_PATH="$HERE/usr/lib:$LD_LIBRARY_PATH"
export PATH="$HERE/usr/bin:$PATH"
exec "$HERE/usr/bin/zupt" "$@"
APPRUN
chmod +x "$OUT/AppRun"

cat > "$OUT/zupt.desktop" <<'DESK'
[Desktop Entry]
Name=Zupt
Comment=Post-quantum backup compression utility
Exec=zupt
Terminal=true
Type=Application
Categories=Utility;Archiving;
Icon=zupt
DESK
cp "$OUT/zupt.desktop" "$OUT/usr/share/applications/"

printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xfc\xcf\xc0\x00\x00\x00\x05\x00\x01\xa5\xf6E@\x00\x00\x00\x00IEND\xaeB`\x82' > "$OUT/zupt.png"
cp "$OUT/zupt.png" "$OUT/usr/share/icons/hicolor/256x256/apps/zupt.png"

if command -v appimagetool >/dev/null 2>&1; then
    ARCH=$ARCH appimagetool "$OUT" "/tmp/${NAME}.AppImage"
    echo "Built: /tmp/${NAME}.AppImage"
else
    cd /tmp
    tar -czf "${NAME}.AppDir.tar.gz" "$(basename "$OUT")"
    echo "appimagetool not present; built AppDir tarball: /tmp/${NAME}.AppDir.tar.gz"
    echo "Users can run: tar xzf ${NAME}.AppDir.tar.gz && ./${NAME}.AppDir/AppRun"
fi
