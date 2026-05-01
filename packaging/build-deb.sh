#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build zupt CLI .deb package
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-2.2.2}"
ARCH="${ARCH:-amd64}"

# Multi-arch lib path mapping (Debian convention)
case "$ARCH" in
    amd64)  MULTIARCH="x86_64-linux-gnu" ;;
    arm64)  MULTIARCH="aarch64-linux-gnu" ;;
    armhf)  MULTIARCH="arm-linux-gnueabihf" ;;
    i386)   MULTIARCH="i386-linux-gnu" ;;
    *)      MULTIARCH="$ARCH-linux-gnu" ;;
esac

PKG="zupt_${VERSION}_${ARCH}"
ROOT="/tmp/$PKG"

rm -rf "$ROOT"
mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/usr/bin" \
         "$ROOT/usr/share/doc/zupt" \
         "$ROOT/usr/share/man/man1"

# Binary
install -m 755 zupt "$ROOT/usr/bin/zupt"

# Note: libzuptsdk.so.2 is provided by the libzuptsdk2 package (separate
# project). We do NOT bundle it. The user must install libzuptsdk2 to
# satisfy the Depends: line below, which gives them the SDK on its own
# upgrade cycle.

# Docs
install -m 644 README.md CHANGELOG.md SECURITY.md AUDIT.md "$ROOT/usr/share/doc/zupt/"
gzip -9n -c CHANGELOG.md > "$ROOT/usr/share/doc/zupt/changelog.gz"

# Man page (use the real one from doc/zupt.1)
if [ -f doc/zupt.1 ]; then
    install -m 644 doc/zupt.1 "$ROOT/usr/share/man/man1/zupt.1"
else
    cat > "$ROOT/usr/share/man/man1/zupt.1" <<'MAN'
.TH ZUPT 1 "April 2026" "zupt 2.2.2" "User Commands"
.SH NAME
zupt \- post-quantum backup compression utility
.SH SYNOPSIS
.B zupt
[\fIcommand\fR] [\fIoptions\fR] \fIarchive\fR [\fIfiles...\fR]
.SH SEE ALSO
Run \fBzupt help\fR for the full options reference.
MAN
fi
gzip -9n "$ROOT/usr/share/man/man1/zupt.1"

# Copyright
cat > "$ROOT/usr/share/doc/zupt/copyright" <<'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: zupt
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

Files: src/vv_*.c src/vaptvupt_api.c include/vv_*.h include/vaptvupt*.h
Copyright: 2025-2026 Cristian Cezar Moisés
License: GPL-3.0+
 The VaptVupt LZ codec is licensed under the GNU General Public License
 version 3 or later (NOT AGPL like the rest of the project). VaptVupt
 is GPL so that, with sufficient maturity, it can be considered for
 upstreaming into the Linux or BSD kernels.
 .
 On Debian systems, the complete text of the GNU General Public
 License version 3 can be found in /usr/share/common-licenses/GPL-3.

Comment:
 Commercial licenses (relief from AGPL/GPL copyleft terms) are
 available for both components. Contact sac@securityops.co for
 commercial inquiries.
COPYRIGHT

# Control
INSTALLED_SIZE=$(du -sk "$ROOT" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<EOF
Package: zupt
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: libc6 (>= 2.28), libargon2-1, libssl3, libzuptsdk2 (>= 2.0.0)
Maintainer: Cristian Cezar Moisés <zupt@riseup.net>
Installed-Size: $INSTALLED_SIZE
Homepage: https://git.securityops.co/cristiancmoises/zupt
Description: Post-quantum backup compression utility
 Zupt is a backup-oriented compression utility with hybrid post-quantum
 encryption (ML-KEM-768 + X25519). It provides authenticated encryption,
 multi-threaded compression, full-disk backup/restore, and integrates
 libzuptsdk for state-of-the-art crypto (HKDF combiner, key commitment,
 HPKE binding, anti-fault decapsulation).
EOF

# Postinst: ldconfig
cat > "$ROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
ldconfig
POSTINST
chmod 755 "$ROOT/DEBIAN/postinst"

cat > "$ROOT/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    ldconfig
fi
POSTRM
chmod 755 "$ROOT/DEBIAN/postrm"

# Build
dpkg-deb -Zxz --build --root-owner-group "$ROOT" "/tmp/$PKG.deb"
echo "Built: /tmp/$PKG.deb"
dpkg-deb --info "/tmp/$PKG.deb" | head -15
