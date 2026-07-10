#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build vaptvupt CLI as AppImage (portable single-file binary).
# Includes a legacy `zupt` symlink so AppDir users can invoke either name.
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-4.2.1}"
ARCH="${ARCH:-x86_64}"
PKGNAME="vaptvupt"
LEGACY="zupt"
NAME="$PKGNAME-$VERSION-$ARCH"
OUT="/tmp/${NAME}.AppDir"

rm -rf "$OUT"
mkdir -p "$OUT/usr/bin" "$OUT/usr/share/applications" "$OUT/usr/share/icons/hicolor/256x256/apps"

# Source-only build: the binary links only libc/libm/pthread from the host,
# so the AppDir ships no bundled libraries.
install -m 755 $PKGNAME "$OUT/usr/bin/$PKGNAME"
ln -sf $PKGNAME "$OUT/usr/bin/$LEGACY"

cat > "$OUT/AppRun" <<APPRUN
#!/bin/bash
HERE="\$(dirname "\$(readlink -f "\${0}")")"
export PATH="\$HERE/usr/bin:\$PATH"
exec "\$HERE/usr/bin/$PKGNAME" "\$@"
APPRUN
chmod +x "$OUT/AppRun"

cat > "$OUT/$PKGNAME.desktop" <<DESK
[Desktop Entry]
Name=VaptVupt
Comment=Post-quantum backup compression utility (formerly Zupt)
Exec=$PKGNAME
Terminal=true
Type=Application
Categories=Utility;Archiving;Security;
Icon=$PKGNAME
DESK
cp "$OUT/$PKGNAME.desktop" "$OUT/usr/share/applications/"

# 1x1 PNG placeholder — replace with a real icon when the brand asset exists
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xfc\xcf\xc0\x00\x00\x00\x05\x00\x01\xa5\xf6E@\x00\x00\x00\x00IEND\xaeB`\x82' > "$OUT/$PKGNAME.png"
cp "$OUT/$PKGNAME.png" "$OUT/usr/share/icons/hicolor/256x256/apps/$PKGNAME.png"

if command -v appimagetool >/dev/null 2>&1; then
    ARCH=$ARCH appimagetool "$OUT" "/tmp/${NAME}.AppImage" 2>&1 | tail -5
    echo "Built: /tmp/${NAME}.AppImage"
fi

# Always produce the AppDir tarball as well -- some environments (no FUSE,
# strict execve policies, etc.) cannot run the .AppImage directly. The
# tarball is the universal fallback: extract and run AppRun.
cd /tmp
tar -czf "${NAME}.AppDir.tar.gz" "$(basename "$OUT")"
echo "Built: /tmp/${NAME}.AppDir.tar.gz"
echo "Users can run: tar xzf ${NAME}.AppDir.tar.gz && ./${NAME}.AppDir/AppRun version"
