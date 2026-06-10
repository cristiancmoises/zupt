#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build zupt-gui .deb (Python/Qt GUI). Works with PyQt6 OR PySide6.
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-1.2.0}"
ARCH="all"
PKG="vaptvupt-gui_${VERSION}_${ARCH}"
ROOT="/tmp/$PKG"

rm -rf "$ROOT"
mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/usr/bin" \
         "$ROOT/usr/lib/vaptvupt-gui" \
         "$ROOT/usr/share/applications" \
         "$ROOT/usr/share/icons/hicolor/256x256/apps" \
         "$ROOT/usr/share/man/man1" \
         "$ROOT/usr/share/doc/vaptvupt-gui"

# Source files
install -m 644 gui/src/zupt_gui.py "$ROOT/usr/lib/vaptvupt-gui/"

# Wrapper script in /usr/bin
cat > "$ROOT/usr/bin/vaptvupt-gui" <<'WRAP'
#!/bin/sh
exec python3 /usr/lib/vaptvupt-gui/zupt_gui.py "$@"
WRAP
chmod 755 "$ROOT/usr/bin/vaptvupt-gui"
# v3.0.0: legacy zupt-gui symlink
ln -sf vaptvupt-gui "$ROOT/usr/bin/zupt-gui"

# Desktop entry
cat > "$ROOT/usr/share/applications/vaptvupt-gui.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=VaptVupt GUI
GenericName=Backup and Compression Utility
Comment=Post-quantum backup with HKDF combiner, key commitment, HPKE binding
Exec=vaptvupt-gui %f
Icon=vaptvupt-gui
Terminal=false
Categories=Utility;Archiving;Compression;Security;
StartupNotify=true
MimeType=application/x-zupt;
Keywords=archive;compression;encryption;post-quantum;backup;
DESKTOP

# Man page
if [ -f doc/vaptvupt-gui.1 ]; then
    install -m 644 doc/vaptvupt-gui.1 "$ROOT/usr/share/man/man1/vaptvupt-gui.1"
    gzip -9n "$ROOT/usr/share/man/man1/vaptvupt-gui.1"
fi

# Icon
if [ -f gui/assets/zupt-icon.png ]; then
    cp gui/assets/zupt-icon.png "$ROOT/usr/share/icons/hicolor/256x256/apps/vaptvupt-gui.png"
else
    python3 -c "
import struct, zlib
def png(w, h, color):
    raw = b''.join(b'\\0' + bytes(color) * w for _ in range(h))
    def chunk(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t+d) & 0xffffffff)
    return b'\\x89PNG\\r\\n\\x1a\\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')
open('$ROOT/usr/share/icons/hicolor/256x256/apps/zupt-gui.png','wb').write(png(256, 256, (88, 92, 215)))
"
fi

# Docs
install -m 644 gui/README.md "$ROOT/usr/share/doc/vaptvupt-gui/" 2>/dev/null || true
gzip -9n -c CHANGELOG.md > "$ROOT/usr/share/doc/vaptvupt-gui/changelog.gz"

cat > "$ROOT/usr/share/doc/vaptvupt-gui/copyright" <<'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: vaptvupt-gui
Upstream-Contact: Cristian Cezar Moisés <zupt@riseup.net>
Source: https://git.securityops.co/cristiancmoises/zupt

Files: *
Copyright: 2025-2026 Cristian Cezar Moisés
License: AGPL-3.0+
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.
 .
 On Debian systems, the complete text of the GNU Affero General Public
 License version 3 can be found in /usr/share/common-licenses/AGPL-3.
COPYRIGHT

# Control
INSTALLED_SIZE=$(du -sk "$ROOT" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<EOF
Package: vaptvupt-gui
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: python3 (>= 3.9), python3-pyqt6 | python3-pyside6, vaptvupt (>= 3.0.0) | zupt (>= 2.2.3)
Provides: zupt-gui (= ${VERSION})
Replaces: zupt-gui (<< 1.2.0)
Conflicts: zupt-gui (<< 1.2.0)
Maintainer: Cristian Cezar Moisés <zupt@riseup.net>
Installed-Size: $INSTALLED_SIZE
Homepage: https://git.securityops.co/cristiancmoises/zupt
Description: Graphical interface for VaptVupt post-quantum backup utility
 PySide6/PyQt6 frontend for VaptVupt (formerly zupt-gui in 1.x). Supports compression, extraction, key
 management, and full disk backup/restore. Exposes both legacy --pq
 and new --pq-sdk (libzuptsdk: HKDF combiner, key commitment, HPKE
 binding, Argon2id) encryption modes.
EOF

# Postinst: refresh icon cache + desktop database, print first-run guidance
cat > "$ROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ -x /usr/bin/update-desktop-database ]; then
    update-desktop-database -q /usr/share/applications || true
fi
if [ -x /usr/bin/gtk-update-icon-cache ]; then
    gtk-update-icon-cache -q /usr/share/icons/hicolor || true
fi

# Friendly first-run check: warn the user if no Qt6 binding is installed.
# We don't fail the install (deb deps already enforce this); we just print
# clear guidance for users who saw "unmet dependencies" earlier.
if ! python3 -c 'import PyQt6.QtWidgets' 2>/dev/null \
   && ! python3 -c 'import PySide6.QtWidgets' 2>/dev/null; then
    cat << 'MSG'

──────────────────────────────────────────────────────────────────────
vaptvupt-gui installed, but no Qt6 Python binding is available.

Install one of the following to enable the GUI:

  Debian/Ubuntu/Mint:   sudo apt install python3-pyqt6
  Fedora/RHEL/Rocky:    sudo dnf install python3-pyqt6
  Arch/Manjaro:         sudo pacman -S python-pyqt6
  pip (any distro):     pip install --user PySide6

After installing the binding, launch with:   vaptvupt-gui
──────────────────────────────────────────────────────────────────────

MSG
fi

# Same friendly warning if zupt CLI not installed.
if ! command -v vaptvupt >/dev/null 2>&1 && ! command -v zupt >/dev/null 2>&1; then
    cat << 'MSG'

──────────────────────────────────────────────────────────────────────
vaptvupt-gui needs the 'vaptvupt' CLI to function. Install it:

  Debian/Ubuntu/Mint:   sudo dpkg -i vaptvupt_3.0.0_amd64.deb
                        (followed by: sudo apt --fix-broken install)
──────────────────────────────────────────────────────────────────────

MSG
fi
exit 0
POSTINST
chmod 755 "$ROOT/DEBIAN/postinst"

cat > "$ROOT/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if [ -x /usr/bin/update-desktop-database ]; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if [ -x /usr/bin/gtk-update-icon-cache ]; then
        gtk-update-icon-cache -q /usr/share/icons/hicolor || true
    fi
fi
POSTRM
chmod 755 "$ROOT/DEBIAN/postrm"

dpkg-deb -Zxz --build --root-owner-group "$ROOT" "/tmp/$PKG.deb"
echo "Built: /tmp/$PKG.deb"
dpkg-deb --info "/tmp/$PKG.deb" | head -12
