#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build zupt-gui AppImage. Since the GUI is pure Python + Qt, the AppDir
# bundles only the Python source and metadata; it relies on system
# python3 + PyQt6/PySide6 at runtime. This keeps the AppImage tiny
# (~50 KB) and lets it work on any Linux with Qt6 Python bindings.
#
# For a true self-contained AppImage with bundled Python interpreter,
# use python-appimage (https://github.com/niess/python-appimage) on
# the build host — it produces a ~80 MB AppImage. The portable variant
# below is the better tradeoff for most distributions.
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-1.1.1}"
APPDIR="/tmp/zupt-gui.AppDir"

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" \
         "$APPDIR/usr/lib/zupt-gui" \
         "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Python source
install -m 644 gui/src/zupt_gui.py "$APPDIR/usr/lib/zupt-gui/"

# Wrapper
cat > "$APPDIR/usr/bin/zupt-gui" <<'WRAP'
#!/bin/sh
exec python3 "$(dirname "$0")/../lib/zupt-gui/zupt_gui.py" "$@"
WRAP
chmod 755 "$APPDIR/usr/bin/zupt-gui"

# Desktop file
cat > "$APPDIR/zupt-gui.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Zupt GUI
GenericName=Backup and Compression Utility
Comment=Post-quantum backup with HKDF combiner, key commitment, HPKE binding
Exec=zupt-gui %f
Icon=zupt-gui
Terminal=false
Categories=Utility;Archiving;Compression;Security;
StartupNotify=true
DESKTOP
cp "$APPDIR/zupt-gui.desktop" "$APPDIR/usr/share/applications/"

# Icon
if [ -f gui/assets/zupt-icon.png ]; then
    cp gui/assets/zupt-icon.png "$APPDIR/zupt-gui.png"
    cp gui/assets/zupt-icon.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/zupt-gui.png"
else
    python3 -c "
import struct, zlib
def png(w, h, color):
    raw = b''.join(b'\\0' + bytes(color) * w for _ in range(h))
    def chunk(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t+d) & 0xffffffff)
    return b'\\x89PNG\\r\\n\\x1a\\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')
open('$APPDIR/zupt-gui.png','wb').write(png(256, 256, (88, 92, 215)))
"
    cp "$APPDIR/zupt-gui.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/zupt-gui.png"
fi

# AppRun — sets PATH so zupt-gui finds the bundled wrapper, falls
# back to system zupt CLI if not present in /usr/bin alongside.
cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
export PATH="$HERE/usr/bin:$PATH"

# Pre-flight check: is python3 available? Is a Qt6 binding installed?
if ! command -v python3 >/dev/null 2>&1; then
    cat >&2 <<EOF
zupt-gui: python3 is not installed.
Install: sudo apt install python3   (Debian/Ubuntu)
         sudo dnf install python3   (Fedora/RHEL)
EOF
    exit 1
fi

if ! python3 -c 'import PyQt6.QtWidgets' 2>/dev/null \
   && ! python3 -c 'import PySide6.QtWidgets' 2>/dev/null; then
    cat >&2 <<EOF
zupt-gui: needs a Qt6 Python binding (PyQt6 or PySide6).
Install one of:
  Debian/Ubuntu:  sudo apt install python3-pyqt6
  Fedora/RHEL:    sudo dnf install python3-pyqt6
  pip (any):      pip install --user PySide6
EOF
    exit 1
fi

if ! command -v zupt >/dev/null 2>&1; then
    cat >&2 <<EOF
zupt-gui: warning — the 'zupt' CLI was not found in PATH.
Install the zupt package or place the binary in PATH.
The GUI will start but compress/extract operations will fail.
EOF
fi

exec "$HERE/usr/bin/zupt-gui" "$@"
APPRUN
chmod 755 "$APPDIR/AppRun"

# Build AppImage
if command -v appimagetool >/dev/null 2>&1; then
    ARCH=x86_64 appimagetool "$APPDIR" "/tmp/Zupt-GUI-$VERSION-x86_64.AppImage" 2>&1 | tail -5
    echo "Built: /tmp/Zupt-GUI-$VERSION-x86_64.AppImage"
else
    cd /tmp
    rm -f "Zupt-GUI-$VERSION-x86_64.AppDir.tar.gz"
    tar -czf "Zupt-GUI-$VERSION-x86_64.AppDir.tar.gz" zupt-gui.AppDir
    cd - >/dev/null
    echo "appimagetool unavailable; portable AppDir tarball at:"
    echo "  /tmp/Zupt-GUI-$VERSION-x86_64.AppDir.tar.gz"
    echo "Run via: tar -xzf ... && ./zupt-gui.AppDir/AppRun"
    echo "Convert to AppImage on a host with appimagetool:"
    echo "  ARCH=x86_64 appimagetool zupt-gui.AppDir Zupt-GUI-$VERSION-x86_64.AppImage"
fi
