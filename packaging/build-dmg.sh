#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Build a macOS .dmg installer for the Zupt CLI.
#
# This script MUST be run on macOS — `hdiutil` is required and only
# ships with macOS. There is no portable way to produce a .dmg from
# Linux that Apple's installer will mount cleanly (libdmg-hfsplus and
# dmg2img exist but produce read-only images that some macOS versions
# reject).
#
# On macOS:
#   xcode-select --install      # one-time, for clang
#   make                        # build the zupt binary
#   VERSION=2.4.7 bash packaging/build-dmg.sh
#
# Produces: /tmp/Zupt-VERSION.dmg with:
#   - zupt binary (universal2 if built with -arch x86_64 -arch arm64)
#   - libzuptsdk dylib alongside the binary at @loader_path
#   - install.command (drag-to-install script)
#   - README.md, LICENSE
#   - Optional: code-signed and notarized if APPLE_DEV_ID env is set
#
# For Homebrew installation, prefer packaging/homebrew/zupt.rb instead.
# The .dmg is for users who don't want to install Homebrew.

set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-2.4.7}"
ARCH="${ARCH:-$(uname -m)}"   # x86_64 or arm64
NAME="Zupt-${VERSION}-${ARCH}"
STAGE="/tmp/${NAME}.app/Contents"

# ── Platform check ──
if [ "$(uname)" != "Darwin" ]; then
    cat >&2 <<EOF
ERROR: build-dmg.sh must be run on macOS.

The .dmg format requires Apple's hdiutil. On Linux:
  - Use the .deb (packaging/build-deb.sh) for Debian/Ubuntu/Mint
  - Use the .rpm (packaging/build-rpm.sh) for Fedora/RHEL/openSUSE
  - Use the AppImage (packaging/build-appimage.sh) for universal Linux
  - Use the Homebrew formula on macOS (packaging/homebrew/zupt.rb)

If you need a macOS .pkg without macOS hardware, GitHub Actions has
macos-14 runners that can produce signed .dmg/.pkg artefacts. See
.github/workflows/ci.yml for the matrix template.
EOF
    exit 1
fi

# ── Build zupt (universal binary if possible) ──
echo "[dmg] Building zupt"
make clean
if xcrun --sdk macosx clang -dM -E - </dev/null | grep -q __aarch64__; then
    # arm64 host → can cross-build for x86_64 via -arch flag
    CFLAGS="-O2 -std=c11 -arch arm64 -arch x86_64" \
    LDFLAGS="-arch arm64 -arch x86_64" \
        make -j"$(sysctl -n hw.ncpu)" || make -j"$(sysctl -n hw.ncpu)"
else
    make -j"$(sysctl -n hw.ncpu)"
fi

# ── Stage the .app bundle ──
echo "[dmg] Staging .app bundle"
rm -rf "/tmp/${NAME}.app"
mkdir -p "$STAGE/MacOS" "$STAGE/Resources" "$STAGE/Frameworks"

install -m 755 zupt "$STAGE/MacOS/zupt"

# Vendored libzuptsdk — on macOS it'd be .dylib, but if the vendored
# build is Linux-style .so, ship that and warn. A proper macOS build
# would produce libzuptsdk.2.0.0.dylib.
if [ -f vendor/zuptsdk/libzuptsdk.2.0.0.dylib ]; then
    install -m 755 vendor/zuptsdk/libzuptsdk.2.0.0.dylib "$STAGE/Frameworks/"
    install_name_tool -id "@loader_path/../Frameworks/libzuptsdk.2.0.0.dylib" \
        "$STAGE/Frameworks/libzuptsdk.2.0.0.dylib"
    install_name_tool -change "vendor/zuptsdk/libzuptsdk.so.2" \
        "@loader_path/../Frameworks/libzuptsdk.2.0.0.dylib" \
        "$STAGE/MacOS/zupt"
elif [ -f vendor/zuptsdk/libzuptsdk.so.2.0.0 ]; then
    cat >&2 <<EOF
WARNING: vendor/zuptsdk ships .so (Linux), not .dylib (macOS).
The .dmg will include the Linux library which won't load on macOS.
Build libzuptsdk natively on macOS first, or modify the Makefile
to produce .dylib output on Darwin.
EOF
    install -m 755 vendor/zuptsdk/libzuptsdk.so.2.0.0 "$STAGE/Frameworks/"
fi

# Info.plist (minimal — zupt is a CLI, so the .app is mostly a wrapper)
cat > "$STAGE/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>co.securityops.zupt</string>
    <key>CFBundleName</key>
    <string>Zupt</string>
    <key>CFBundleDisplayName</key>
    <string>Zupt</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleExecutable</key>
    <string>zupt</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
</dict>
</plist>
PLIST

cp README.md "$STAGE/Resources/" 2>/dev/null || true
cp LICENSE   "$STAGE/Resources/" 2>/dev/null || true

# ── Drag-to-install command file ──
cat > "/tmp/${NAME}-install.command" <<'INSTALL'
#!/bin/bash
# Drag-installer for Zupt CLI. Copies the binary to /usr/local/bin
# (or the user's ~/bin if /usr/local isn't writable).
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$DIR/Zupt.app"
TARGET="/usr/local/bin"
if [ ! -w "$TARGET" ]; then
    TARGET="$HOME/bin"
    mkdir -p "$TARGET"
    echo "Installing to $TARGET (add to PATH if missing)"
fi
cp "$APP/Contents/MacOS/zupt" "$TARGET/zupt"
chmod 755 "$TARGET/zupt"
# Bundle the dylib alongside under a stable path
LIBDIR="/usr/local/lib/zupt"
[ -w /usr/local/lib ] || LIBDIR="$HOME/lib/zupt"
mkdir -p "$LIBDIR"
if [ -d "$APP/Contents/Frameworks" ]; then
    cp -P "$APP/Contents/Frameworks"/* "$LIBDIR/" 2>/dev/null || true
fi
echo "Installed: $TARGET/zupt"
"$TARGET/zupt" version
INSTALL
chmod 755 "/tmp/${NAME}-install.command"

# ── Optional: code sign ──
if [ -n "${APPLE_DEV_ID:-}" ]; then
    echo "[dmg] Code-signing with Developer ID: $APPLE_DEV_ID"
    codesign --force --options runtime --sign "$APPLE_DEV_ID" \
        --entitlements packaging/macos/entitlements.plist \
        "$STAGE/MacOS/zupt" 2>&1 || echo "  (no entitlements file — proceeding unsigned for hardening)"
    codesign --force --sign "$APPLE_DEV_ID" "/tmp/${NAME}.app" || true
fi

# ── Build .dmg ──
echo "[dmg] Building disk image"
DMG="/tmp/${NAME}.dmg"
rm -f "$DMG"

# Stage a directory tree that becomes the .dmg root
DMGSRC="/tmp/${NAME}-dmgsrc"
rm -rf "$DMGSRC"
mkdir -p "$DMGSRC"
cp -R "/tmp/${NAME}.app" "$DMGSRC/Zupt.app"
cp "/tmp/${NAME}-install.command" "$DMGSRC/Install Zupt.command"
[ -f README.md ] && cp README.md "$DMGSRC/"
[ -f LICENSE   ] && cp LICENSE   "$DMGSRC/"

hdiutil create -fs HFS+ -srcfolder "$DMGSRC" -volname "Zupt ${VERSION}" \
    -format UDZO -ov "$DMG"

# ── Optional: notarize ──
if [ -n "${APPLE_DEV_ID:-}" ] && [ -n "${APPLE_NOTARIZE_KEY:-}" ]; then
    echo "[dmg] Submitting for notarization"
    xcrun notarytool submit "$DMG" --apple-id "$APPLE_DEV_ID" \
        --password "$APPLE_NOTARIZE_KEY" --wait
    xcrun stapler staple "$DMG"
fi

echo ""
echo "Built: $DMG ($(du -h "$DMG" | cut -f1))"
echo "Users mount and drag 'Zupt.app' or double-click 'Install Zupt.command'."
