#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Build self-contained vaptvupt CLI .deb package.
#
# v3.0.0 rename: the binary is now `vaptvupt`; we install it at
# /usr/bin/vaptvupt and create /usr/bin/zupt → /usr/bin/vaptvupt as
# a legacy symlink for one major version cycle. The package name
# is `vaptvupt` with Provides/Replaces/Conflicts on `zupt` so
# `apt install zupt` still resolves cleanly.
#
# Bundles libzuptsdk.so.2 under /usr/lib/vaptvupt/ so users do NOT
# need to separately install the libzuptsdk package.

set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-3.0.0}"
ARCH="${ARCH:-amd64}"
PKGNAME="vaptvupt"
LEGACY="zupt"

PKG="${PKGNAME}_${VERSION}_${ARCH}"
ROOT="/tmp/$PKG"

# Vendored libzuptsdk path (relative to project root)
SDK_LIB="vendor/zuptsdk/libzuptsdk.so.2.0.0"
if [ ! -f "$SDK_LIB" ]; then
    echo "ERROR: $SDK_LIB not found. Vendor the libzuptsdk shared object first." >&2
    exit 1
fi
PQVV_LIB="vendor/pqvaptvupt/libpqvaptvupt.so.0.6.0"
if [ ! -f "$PQVV_LIB" ]; then
    echo "ERROR: $PQVV_LIB not found. Vendor the libpqvaptvupt shared object first." >&2
    exit 1
fi

echo "[deb] Building vaptvupt"
make clean >/dev/null 2>&1 || true
make -j"$(nproc)" >/dev/null

echo "[deb] Patching rpath -> /usr/lib/$PKGNAME:/usr/lib64/$PKGNAME"
patchelf --set-rpath "/usr/lib/$PKGNAME:/usr/lib64/$PKGNAME" $PKGNAME

if ! readelf -d $PKGNAME | grep -q "RUNPATH.*\[/usr/lib/$PKGNAME:/usr/lib64/$PKGNAME\]"; then
    echo "ERROR: built $PKGNAME does not have correct RUNPATH" >&2
    readelf -d $PKGNAME | grep -E "RPATH|RUNPATH"
    exit 1
fi

rm -rf "$ROOT"
mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/usr/bin" \
         "$ROOT/usr/lib/$PKGNAME" \
         "$ROOT/usr/share/doc/$PKGNAME" \
         "$ROOT/usr/share/man/man1" \
         "$ROOT/usr/share/bash-completion/completions" \
         "$ROOT/usr/share/zsh/site-functions" \
         "$ROOT/usr/share/fish/vendor_completions.d"

# Binary + legacy symlink
install -m 755 $PKGNAME "$ROOT/usr/bin/$PKGNAME"
ln -sf $PKGNAME "$ROOT/usr/bin/$LEGACY"

# Bundled libzuptsdk
install -m 755 "$SDK_LIB" "$ROOT/usr/lib/$PKGNAME/libzuptsdk.so.2.0.0"
ln -sf libzuptsdk.so.2.0.0 "$ROOT/usr/lib/$PKGNAME/libzuptsdk.so.2"
ln -sf libzuptsdk.so.2.0.0 "$ROOT/usr/lib/$PKGNAME/libzuptsdk.so"
install -m 755 "$PQVV_LIB" "$ROOT/usr/lib/$PKGNAME/libpqvaptvupt.so.0.6.0"
ln -sf libpqvaptvupt.so.0.6.0 "$ROOT/usr/lib/$PKGNAME/libpqvaptvupt.so.0"
ln -sf libpqvaptvupt.so.0.6.0 "$ROOT/usr/lib/$PKGNAME/libpqvaptvupt.so"

# Manpage (gzip-compressed); install + legacy alias
if [ -f doc/vaptvupt.1 ]; then
    gzip -9n -c doc/vaptvupt.1 > "$ROOT/usr/share/man/man1/$PKGNAME.1.gz"
    ln -sf $PKGNAME.1.gz "$ROOT/usr/share/man/man1/$LEGACY.1.gz"
fi

# Shell completions
if [ -f completions/vaptvupt.bash ]; then
    install -m 0644 completions/vaptvupt.bash "$ROOT/usr/share/bash-completion/completions/$PKGNAME"
    ln -sf $PKGNAME "$ROOT/usr/share/bash-completion/completions/$LEGACY"
fi
if [ -f completions/_vaptvupt ]; then
    install -m 0644 completions/_vaptvupt "$ROOT/usr/share/zsh/site-functions/_$PKGNAME"
    ln -sf _$PKGNAME "$ROOT/usr/share/zsh/site-functions/_$LEGACY"
fi
if [ -f completions/vaptvupt.fish ]; then
    install -m 0644 completions/vaptvupt.fish "$ROOT/usr/share/fish/vendor_completions.d/$PKGNAME.fish"
fi

# Docs
install -m 0644 README.md "$ROOT/usr/share/doc/$PKGNAME/README.md"
install -m 0644 LICENSE   "$ROOT/usr/share/doc/$PKGNAME/copyright"
[ -f SECURITY.md ]      && install -m 0644 SECURITY.md      "$ROOT/usr/share/doc/$PKGNAME/SECURITY.md"
[ -f CHANGELOG.md ]     && install -m 0644 CHANGELOG.md     "$ROOT/usr/share/doc/$PKGNAME/CHANGELOG.md"
[ -f THREAT_MODEL.md ]  && install -m 0644 THREAT_MODEL.md  "$ROOT/usr/share/doc/$PKGNAME/THREAT_MODEL.md"

# DEBIAN/control
INSTALLED_KB=$(du -sk "$ROOT/usr" | awk '{print $1}')
cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKGNAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Provides: $LEGACY (= $VERSION)
Replaces: $LEGACY (<< 3.0.0)
Conflicts: $LEGACY (<< 3.0.0)
Depends: libargon2-1, libssl3 | libssl3t64
Installed-Size: $INSTALLED_KB
Maintainer: Cristian Cezar Moisés <sac@securityops.co>
Homepage: https://git.securityops.co/cristiancmoises/zupt
Description: Post-quantum backup compression utility (formerly zupt)
 VaptVupt (renamed from Zupt in v3.0.0 due to a prior INPI Brasil
 trademark on the name) is a pure-C11 backup compression utility
 featuring post-quantum hybrid encryption (ML-KEM-768 + X25519,
 FIPS 203), AES-256-CTR + HMAC-SHA256 authenticated encryption,
 Argon2id KDF (PBKDF2-SHA256 via --kdf pbkdf2), multi-threaded
 compression with the VaptVupt LZ + ANS codec 2.48.5, full-disk
 backup with sparse-region detection, and end-to-end byte-level
 tamper detection on encrypted archives (F-09: 0/1827 silent
 accepts).
 .
 The .zupt archive extension is unchanged; v2.x and v3.0.0
 archives are bidirectionally compatible. The legacy /usr/bin/zupt
 symlink is preserved for one major version cycle.
EOF

DEB_OUT="/tmp/${PKGNAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$ROOT" "$DEB_OUT" >/dev/null
echo "Built: $DEB_OUT ($(du -h "$DEB_OUT" | cut -f1))"
dpkg-deb -I "$DEB_OUT" | sed -n '1,20p'
