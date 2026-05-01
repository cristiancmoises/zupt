#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build zupt-gui RPM. Falls back to SRPM-equivalent tarball if rpmbuild absent.
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-1.1.1}"
RPMROOT="/tmp/rpmbuild-zupt-gui"
rm -rf "$RPMROOT"
mkdir -p "$RPMROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

TMP="/tmp/zupt-gui-$VERSION"
rm -rf "$TMP" && mkdir -p "$TMP/src" "$TMP/doc" "$TMP/assets"
cp gui/src/zupt_gui.py "$TMP/src/"
cp doc/zupt-gui.1 "$TMP/doc/" 2>/dev/null || true
cp gui/README.md "$TMP/" 2>/dev/null || true
cp LICENSE "$TMP/" 2>/dev/null || true
[ -f gui/assets/zupt-icon.png ] && cp gui/assets/zupt-icon.png "$TMP/assets/"
tar -czf "$RPMROOT/SOURCES/zupt-gui-$VERSION.tar.gz" -C /tmp "zupt-gui-$VERSION"

cat > "$RPMROOT/SPECS/zupt-gui.spec" <<EOF
Name:           zupt-gui
Version:        $VERSION
Release:        1%{?dist}
Summary:        Graphical interface for the Zupt post-quantum backup utility
License:        AGPL-3.0-or-later
URL:            https://git.securityops.co/cristiancmoises/zupt
Source0:        zupt-gui-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python3 >= 3.9
Requires:       python3 >= 3.9
Requires:       (python3-qt6 or python3-pyside6 or python3-pyqt6)
Requires:       zupt >= 2.2.2

%description
PySide6/PyQt6 frontend for Zupt. Supports compression, extraction, key
management, and full disk backup/restore. Exposes both legacy --pq and
new --pq-sdk (libzuptsdk: HKDF combiner, key commitment, HPKE binding,
Argon2id) encryption modes. Auto-detects whichever Qt6 binding is
installed at startup.

%prep
%autosetup

%build
# nothing to build; pure Python

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/zupt-gui
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/256x256/apps
mkdir -p %{buildroot}%{_mandir}/man1

install -m 644 src/zupt_gui.py %{buildroot}%{_libdir}/zupt-gui/

cat > %{buildroot}%{_bindir}/zupt-gui <<'WRAP'
#!/bin/sh
exec python3 %{_libdir}/zupt-gui/zupt_gui.py "\$@"
WRAP
chmod 755 %{buildroot}%{_bindir}/zupt-gui

cat > %{buildroot}%{_datadir}/applications/zupt-gui.desktop <<'DESKTOP'
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

[ -f doc/zupt-gui.1 ] && install -m 644 doc/zupt-gui.1 %{buildroot}%{_mandir}/man1/
[ -f assets/zupt-icon.png ] && install -m 644 assets/zupt-icon.png %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/zupt-gui.png || true

# Generate placeholder icon if no real one exists
if [ ! -f %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/zupt-gui.png ]; then
    python3 -c "
import struct, zlib
def png(w, h, color):
    raw = b''.join(b'\\0' + bytes(color) * w for _ in range(h))
    def chunk(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t+d) & 0xffffffff)
    return b'\\x89PNG\\r\\n\\x1a\\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')
open('%{buildroot}%{_datadir}/icons/hicolor/256x256/apps/zupt-gui.png','wb').write(png(256, 256, (88, 92, 215)))
"
fi

%post
if [ -x /usr/bin/update-desktop-database ]; then
    update-desktop-database -q /usr/share/applications || :
fi
if [ -x /usr/bin/gtk-update-icon-cache ]; then
    gtk-update-icon-cache -q /usr/share/icons/hicolor || :
fi

%postun
if [ \$1 -eq 0 ]; then
    if [ -x /usr/bin/update-desktop-database ]; then
        update-desktop-database -q /usr/share/applications || :
    fi
fi

%files
%doc README.md
%license LICENSE
%{_bindir}/zupt-gui
%{_libdir}/zupt-gui/zupt_gui.py
%{_datadir}/applications/zupt-gui.desktop
%{_datadir}/icons/hicolor/256x256/apps/zupt-gui.png
%{_mandir}/man1/zupt-gui.1*

%changelog
* Mon Apr 27 2026 Cristian Cezar Moisés <zupt@riseup.net> - $VERSION-1
- Cross-binding (PySide6 OR PyQt6 auto-detected)
- SDK v2 mode toggles in compress/extract/keygen tabs
- Man page added
EOF

if command -v rpmbuild >/dev/null 2>&1; then
    rpmbuild --define "_topdir $RPMROOT" -bb "$RPMROOT/SPECS/zupt-gui.spec" 2>&1 | tail -3
    cp "$RPMROOT/RPMS/noarch/zupt-gui-$VERSION-1."*.rpm /tmp/ 2>/dev/null || true
    ls /tmp/zupt-gui-$VERSION-*.rpm 2>/dev/null
else
    SRPM_TAR="/tmp/zupt-gui-$VERSION.srpm.tar.gz"
    tar -czf "$SRPM_TAR" -C "$RPMROOT" SPECS SOURCES
    echo "rpmbuild unavailable; SRPM-equivalent at: $SRPM_TAR"
fi
