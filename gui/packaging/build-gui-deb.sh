#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build zupt-gui .deb package
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-2.2.1}"
ARCH="all"
PKG="zupt-gui_${VERSION}_${ARCH}"
ROOT="/tmp/$PKG"

rm -rf "$ROOT"
mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/usr/bin" \
         "$ROOT/usr/lib/python3/dist-packages" \
         "$ROOT/usr/share/applications" \
         "$ROOT/usr/share/icons/hicolor/256x256/apps" \
         "$ROOT/usr/share/doc/zupt-gui"

# Python module
install -m 644 src/zupt_gui.py "$ROOT/usr/lib/python3/dist-packages/zupt_gui.py"

# Launcher
cat > "$ROOT/usr/bin/zupt-gui" <<'LAUNCH'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/usr/lib/python3/dist-packages")
from zupt_gui import main
sys.exit(main())
LAUNCH
chmod +x "$ROOT/usr/bin/zupt-gui"

# Desktop file
install -m 644 packaging/zupt-gui.desktop "$ROOT/usr/share/applications/" 2>/dev/null || cat > "$ROOT/usr/share/applications/zupt-gui.desktop" <<'DESK'
[Desktop Entry]
Name=Zupt GUI
GenericName=Post-Quantum Backup Utility
Comment=Compress and encrypt files with hybrid PQ crypto
Exec=zupt-gui
Terminal=false
Type=Application
Categories=Utility;Archiving;Security;
Icon=zupt-gui
DESK

# Icon (use a real one if assets exist)
if [ -f assets/zupt-256.png ]; then
    install -m 644 assets/zupt-256.png "$ROOT/usr/share/icons/hicolor/256x256/apps/zupt-gui.png"
elif [ -d ../assets ] && [ -f ../assets/zupt-256.png ]; then
    install -m 644 ../assets/zupt-256.png "$ROOT/usr/share/icons/hicolor/256x256/apps/zupt-gui.png"
else
    # 1×1 placeholder
    printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xfc\xcf\xc0\x00\x00\x00\x05\x00\x01\xa5\xf6E@\x00\x00\x00\x00IEND\xaeB`\x82' > "$ROOT/usr/share/icons/hicolor/256x256/apps/zupt-gui.png"
fi

# Docs
install -m 644 README.md "$ROOT/usr/share/doc/zupt-gui/"
gzip -9n -c ../CHANGELOG.md > "$ROOT/usr/share/doc/zupt-gui/changelog.gz" 2>/dev/null || true

cat > "$ROOT/usr/share/doc/zupt-gui/copyright" <<'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: zupt-gui
Upstream-Contact: Cristian Cezar Moisés <zupt@riseup.net>
Source: https://git.securityops.co/cristiancmoises/zupt

Files: *
Copyright: 2025-2026 Cristian Cezar Moisés
License: AGPL-3.0+
COPYRIGHT

INSTALLED_SIZE=$(du -sk "$ROOT" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<EOF
Package: zupt-gui
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: python3 (>= 3.9), python3-pyside6, zupt (>= 2.2.0)
Maintainer: Cristian Cezar Moisés <zupt@riseup.net>
Installed-Size: $INSTALLED_SIZE
Homepage: https://git.securityops.co/cristiancmoises/zupt
Description: Zupt GUI — Post-Quantum Backup Utility
 Cross-platform graphical interface for the zupt backup compression
 utility with post-quantum hybrid encryption (ML-KEM-768 + X25519).
 .
 v2.2+ uses libzuptsdk under the hood for HKDF-SHA3 hybrid combiner,
 32-byte key commitment, HPKE binding (RFC 9180), and anti-fault
 double-decapsulation. Supports legacy archives via auto-detection.
EOF

dpkg-deb --build --root-owner-group "$ROOT" "/tmp/$PKG.deb"
echo "Built: /tmp/$PKG.deb"
dpkg-deb --info "/tmp/$PKG.deb" | head -12
