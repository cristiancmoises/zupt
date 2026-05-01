#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build Zupt GUI AppImage
# Requires: appimagetool, python3, pip
set -e

APP="zupt-gui"
VERSION="1.0.0"
APPDIR="${APP}.AppDir"

rm -rf "$APPDIR" "${APP}-${VERSION}-x86_64.AppImage"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/zupt-gui" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Install Python + deps into AppDir
python3 -m venv "$APPDIR/usr/python"
"$APPDIR/usr/python/bin/pip" install PySide6 --quiet

# Copy app
cp ../../src/zupt_gui.py "$APPDIR/usr/share/zupt-gui/"
cp ../../assets/zupt.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/zupt-gui.png" 2>/dev/null || true

# Create launcher
cat > "$APPDIR/AppRun" << 'APPRUN'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
export PATH="$HERE/usr/bin:$HERE/usr/python/bin:$PATH"
exec python3 "$HERE/usr/share/zupt-gui/zupt_gui.py" "$@"
APPRUN
chmod +x "$APPDIR/AppRun"

# Desktop file
cat > "$APPDIR/${APP}.desktop" << DESKTOP
[Desktop Entry]
Type=Application
Name=Zupt GUI
Comment=Post-Quantum Backup Utility
Exec=zupt-gui
Icon=zupt-gui
Categories=Utility;Archiving;Security;
Terminal=false
DESKTOP

# Build AppImage
if command -v appimagetool >/dev/null; then
    ARCH=x86_64 appimagetool "$APPDIR" "${APP}-${VERSION}-x86_64.AppImage"
    echo "Built: ${APP}-${VERSION}-x86_64.AppImage"
else
    echo "appimagetool not found. Install from https://github.com/AppImage/AppImageKit"
    echo "AppDir ready at: $APPDIR/"
fi
