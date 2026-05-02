#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build self-contained zupt CLI .deb package.
# Bundles libzuptsdk.so.2 under /usr/lib/zupt/ so users do NOT need to
# separately install the libzuptsdk package.
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-2.2.3}"
ARCH="${ARCH:-amd64}"

PKG="zupt_${VERSION}_${ARCH}"
ROOT="/tmp/$PKG"

# Vendored libzuptsdk path (relative to project root)
SDK_LIB="vendor/zuptsdk/libzuptsdk.so.2.0.0"
if [ ! -f "$SDK_LIB" ]; then
    echo "ERROR: $SDK_LIB not found. Vendor the libzuptsdk shared object first." >&2
    exit 1
fi

# Rebuild zupt fresh, then patch the rpath to point at /usr/lib/zupt
echo "[deb] Building zupt"
make clean >/dev/null 2>&1 || true
make -j"$(nproc)" >/dev/null

echo "[deb] Patching rpath -> /usr/lib/zupt:/usr/lib64/zupt"
patchelf --set-rpath '/usr/lib/zupt:/usr/lib64/zupt' zupt

# Verify rpath was applied
if ! readelf -d zupt | grep -q "RUNPATH.*\[/usr/lib/zupt:/usr/lib64/zupt\]"; then
    echo "ERROR: built zupt does not have correct RUNPATH" >&2
    readelf -d zupt | grep -E "RPATH|RUNPATH"
    exit 1
fi

rm -rf "$ROOT"
mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/usr/bin" \
         "$ROOT/usr/lib/zupt" \
         "$ROOT/usr/share/doc/zupt" \
         "$ROOT/usr/share/man/man1"

# Binary
install -m 755 zupt "$ROOT/usr/bin/zupt"

# Bundled libzuptsdk
install -m 755 "$SDK_LIB" "$ROOT/usr/lib/zupt/libzuptsdk.so.2.0.0"
ln -sf libzuptsdk.so.2.0.0 "$ROOT/usr/lib/zupt/libzuptsdk.so.2"
ln -sf libzuptsdk.so.2.0.0 "$ROOT/usr/lib/zupt/libzuptsdk.so"

# Docs
install -m 644 README.md CHANGELOG.md SECURITY.md AUDIT.md "$ROOT/usr/share/doc/zupt/"
gzip -9n -c CHANGELOG.md > "$ROOT/usr/share/doc/zupt/changelog.gz"

# Man page
if [ -f doc/zupt.1 ]; then
    install -m 644 doc/zupt.1 "$ROOT/usr/share/man/man1/zupt.1"
else
    cat > "$ROOT/usr/share/man/man1/zupt.1" <<MAN
.TH ZUPT 1 "May 2026" "zupt $VERSION" "User Commands"
.SH NAME
zupt \\- post-quantum backup compression utility
.SH SYNOPSIS
.B zupt
[\\fIcommand\\fR] [\\fIoptions\\fR] \\fIarchive\\fR [\\fIfiles...\\fR]
.SH SEE ALSO
Run \\fBzupt help\\fR for the full options reference.
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

Files: usr/lib/zupt/libzuptsdk.so.*
Copyright: 2025-2026 Cristian Cezar Moisés
License: AGPL-3.0+
 Bundled libzuptsdk shared object is part of the upstream libzuptsdk
 project, AGPL-3.0+. Source: https://git.securityops.co/cristiancmoises/libzuptsdk

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
Depends: libc6 (>= 2.28), libargon2-1, libssl3
Maintainer: Cristian Cezar Moisés <zupt@riseup.net>
Installed-Size: $INSTALLED_SIZE
Homepage: https://git.securityops.co/cristiancmoises/zupt
Description: Post-quantum backup compression utility
 Zupt is a backup-oriented compression utility with hybrid post-quantum
 encryption (ML-KEM-768 + X25519). It provides AES-256-CTR + HMAC-SHA256
 authenticated encryption, multi-threaded compression, full-disk
 backup/restore, block-level deduplication, and embeds the VaptVupt
 2.48.2 codec for high-throughput LZ77 + tANS compression with AVX2
 and NEON SIMD acceleration. The libzuptsdk shared library is bundled
 under /usr/lib/zupt -- no separate package required.
EOF

# Postinst / Postrm: nothing needed; libzuptsdk is found via RPATH
cat > "$ROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
exit 0
POSTINST
chmod 755 "$ROOT/DEBIAN/postinst"

cat > "$ROOT/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
exit 0
POSTRM
chmod 755 "$ROOT/DEBIAN/postrm"

# Build
dpkg-deb -Zxz --build --root-owner-group "$ROOT" "/tmp/$PKG.deb"
echo ""
echo "Built: /tmp/$PKG.deb ($(du -h /tmp/$PKG.deb | cut -f1))"
dpkg-deb --info "/tmp/$PKG.deb" | head -20
echo ""
echo "Contents:"
dpkg-deb --contents "/tmp/$PKG.deb" | head -20
