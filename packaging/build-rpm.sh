#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Build self-contained vaptvupt RPM (formerly zupt). Bundles
# libzuptsdk.so.2 under /usr/lib/vaptvupt/ so users do NOT need
# a separate libzuptsdk package. Installs a legacy /usr/bin/zupt
# symlink for one major version cycle.

set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-3.0.0}"
ARCH="${ARCH:-x86_64}"
RELEASE="1"
PKGNAME="vaptvupt"
LEGACY="zupt"

SDK_LIB="vendor/zuptsdk/libzuptsdk.so.2.0.0"
if [ ! -f "$SDK_LIB" ]; then
    echo "ERROR: $SDK_LIB not found." >&2
    exit 1
fi

echo "[rpm] Building $PKGNAME"
make clean >/dev/null 2>&1 || true
make -j"$(nproc)" >/dev/null
echo "[rpm] Patching rpath -> /usr/lib/$PKGNAME:/usr/lib64/$PKGNAME"
patchelf --set-rpath "/usr/lib/$PKGNAME:/usr/lib64/$PKGNAME" $PKGNAME
if ! readelf -d $PKGNAME | grep -q "RUNPATH.*\[/usr/lib/$PKGNAME:/usr/lib64/$PKGNAME\]"; then
    echo "ERROR: $PKGNAME does not have correct RUNPATH" >&2
    exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "[rpm] rpmbuild not found; install rpm package to proceed"
    exit 1
fi

RPMROOT="/tmp/rpmbuild-$PKGNAME"
rm -rf "$RPMROOT"
mkdir -p "$RPMROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

STAGE="/tmp/$PKGNAME-rpm-stage-${VERSION}"
rm -rf "$STAGE"
mkdir -p "$STAGE/$PKGNAME-${VERSION}/completions"

cp $PKGNAME "$STAGE/$PKGNAME-${VERSION}/$PKGNAME"
cp "$SDK_LIB" "$STAGE/$PKGNAME-${VERSION}/libzuptsdk.so.2.0.0"
cp "vendor/pqvaptvupt/libpqvaptvupt.so.0.6.0" "$STAGE/$PKGNAME-${VERSION}/libpqvaptvupt.so.0.6.0"
cp README.md CHANGELOG.md SECURITY.md AUDIT.md LICENSE "$STAGE/$PKGNAME-${VERSION}/"
[ -f doc/vaptvupt.1 ] && cp doc/vaptvupt.1 "$STAGE/$PKGNAME-${VERSION}/$PKGNAME.1"
[ -f completions/vaptvupt.bash ] && cp completions/vaptvupt.bash "$STAGE/$PKGNAME-${VERSION}/completions/"
[ -f completions/_vaptvupt ]     && cp completions/_vaptvupt     "$STAGE/$PKGNAME-${VERSION}/completions/"
[ -f completions/vaptvupt.fish ] && cp completions/vaptvupt.fish "$STAGE/$PKGNAME-${VERSION}/completions/"
tar -czf "$RPMROOT/SOURCES/$PKGNAME-${VERSION}.tar.gz" -C "$STAGE" "$PKGNAME-${VERSION}"

cat > "$RPMROOT/SPECS/$PKGNAME.spec" <<EOF
Name:           $PKGNAME
Version:        $VERSION
Release:        ${RELEASE}%{?dist}
Summary:        Post-quantum backup compression utility (formerly zupt)
License:        AGPL-3.0-or-later AND GPL-3.0-or-later
URL:            https://git.securityops.co/cristiancmoises/zupt
Source0:        $PKGNAME-%{version}.tar.gz

# v3.0.0 rename — INPI Brasil trademark on the prior name "Zupt".
# Cleanly supersede legacy 'zupt' RPMs.
Provides:       $LEGACY = %{version}-%{release}
Obsoletes:      $LEGACY < 3.0.0
Conflicts:      $LEGACY < 3.0.0

Requires:       libargon2
Requires:       openssl-libs >= 3.0
AutoReqProv:    no

%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

%description
VaptVupt (renamed from Zupt in v3.0.0 due to INPI Brasil trademark
on the prior name) is a backup-oriented compression utility with
hybrid post-quantum encryption (ML-KEM-768 + X25519). Provides
AES-256-CTR + HMAC-SHA256 authenticated encryption, multi-threaded
compression, full-disk backup/restore, block-level deduplication,
and embeds the VaptVupt 2.48.5 LZ + ANS codec with AVX2 and NEON
SIMD acceleration. The libzuptsdk shared library is bundled under
/usr/lib/$PKGNAME -- no separate package required.

The on-disk archive extension is unchanged (.zupt); v2.x and v3.0.0
archives are bidirectionally compatible. The legacy /usr/bin/zupt
symlink is preserved for one major version cycle.

%prep
%setup -q

%build
# Pre-built before rpmbuild was invoked; nothing to do.

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/$PKGNAME
mkdir -p %{buildroot}%{_docdir}/$PKGNAME
mkdir -p %{buildroot}%{_licensedir}/$PKGNAME
mkdir -p %{buildroot}%{_mandir}/man1
mkdir -p %{buildroot}%{_datadir}/bash-completion/completions
mkdir -p %{buildroot}%{_datadir}/zsh/site-functions
mkdir -p %{buildroot}%{_datadir}/fish/vendor_completions.d

install -m 755 $PKGNAME %{buildroot}%{_bindir}/$PKGNAME
ln -sf $PKGNAME %{buildroot}%{_bindir}/$LEGACY

install -m 755 libzuptsdk.so.2.0.0 %{buildroot}%{_libdir}/$PKGNAME/libzuptsdk.so.2.0.0
ln -sf libzuptsdk.so.2.0.0 %{buildroot}%{_libdir}/$PKGNAME/libzuptsdk.so.2
ln -sf libzuptsdk.so.2.0.0 %{buildroot}%{_libdir}/$PKGNAME/libzuptsdk.so
install -m 755 libpqvaptvupt.so.0.6.0 %{buildroot}%{_libdir}/$PKGNAME/libpqvaptvupt.so.0.6.0
ln -sf libpqvaptvupt.so.0.6.0 %{buildroot}%{_libdir}/$PKGNAME/libpqvaptvupt.so.0
ln -sf libpqvaptvupt.so.0.6.0 %{buildroot}%{_libdir}/$PKGNAME/libpqvaptvupt.so

install -m 644 README.md CHANGELOG.md SECURITY.md AUDIT.md %{buildroot}%{_docdir}/$PKGNAME/
install -m 644 LICENSE %{buildroot}%{_licensedir}/$PKGNAME/

if [ -f $PKGNAME.1 ]; then
    install -m 644 $PKGNAME.1 %{buildroot}%{_mandir}/man1/$PKGNAME.1
    gzip -9n %{buildroot}%{_mandir}/man1/$PKGNAME.1
    ln -sf $PKGNAME.1.gz %{buildroot}%{_mandir}/man1/$LEGACY.1.gz
fi

if [ -f completions/vaptvupt.bash ]; then
    install -m 644 completions/vaptvupt.bash %{buildroot}%{_datadir}/bash-completion/completions/$PKGNAME
    ln -sf $PKGNAME %{buildroot}%{_datadir}/bash-completion/completions/$LEGACY
fi
if [ -f completions/_vaptvupt ]; then
    install -m 644 completions/_vaptvupt %{buildroot}%{_datadir}/zsh/site-functions/_$PKGNAME
    ln -sf _$PKGNAME %{buildroot}%{_datadir}/zsh/site-functions/_$LEGACY
fi
if [ -f completions/vaptvupt.fish ]; then
    install -m 644 completions/vaptvupt.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/$PKGNAME.fish
fi

%files
%license %{_licensedir}/$PKGNAME/LICENSE
%doc %{_docdir}/$PKGNAME/README.md
%doc %{_docdir}/$PKGNAME/CHANGELOG.md
%doc %{_docdir}/$PKGNAME/SECURITY.md
%doc %{_docdir}/$PKGNAME/AUDIT.md
%{_bindir}/$PKGNAME
%{_bindir}/$LEGACY
%dir %{_libdir}/$PKGNAME
%{_libdir}/$PKGNAME/libzuptsdk.so
%{_libdir}/$PKGNAME/libzuptsdk.so.2
%{_libdir}/$PKGNAME/libzuptsdk.so.2.0.0
%{_libdir}/$PKGNAME/libpqvaptvupt.so
%{_libdir}/$PKGNAME/libpqvaptvupt.so.0
%{_libdir}/$PKGNAME/libpqvaptvupt.so.0.6.0
%{_mandir}/man1/$PKGNAME.1.gz
%{_mandir}/man1/$LEGACY.1.gz
%{_datadir}/bash-completion/completions/$PKGNAME
%{_datadir}/bash-completion/completions/$LEGACY
%{_datadir}/zsh/site-functions/_$PKGNAME
%{_datadir}/zsh/site-functions/_$LEGACY
%{_datadir}/fish/vendor_completions.d/$PKGNAME.fish

%changelog
* Sun May 25 2026 Cristian Cezar Moises <zupt@riseup.net> - $VERSION-$RELEASE
- v3.0.0: Renamed from "Zupt" to "VaptVupt" because of a prior INPI
  Brasil trademark on "Zupt". Archive extension .zupt is preserved;
  v2.x and v3.0.0 archives are bidirectionally compatible. Legacy
  /usr/bin/zupt is installed as a symlink to /usr/bin/vaptvupt.
- Integrated VaptVupt LZ + ANS codec 2.48.5: fixes csz==0 heap-
  buffer-overflow READ in vv_dstream_decompress_chunk (libFuzzer-
  found, medium severity), UBSan-safe pointer arithmetic in
  vv_copy_match.
- Enhanced manpage (597 lines, was 422): POST-QUANTUM ENCRYPTION,
  PERFORMANCE table, SECURITY/threat-model, ENVIRONMENT and
  EXIT STATUS sections.
- Fixed GUI binary-discovery bug (PATH-missing-/usr/bin scenario);
  GUI now does liveness check + logs discovery to stderr with
  VAPTVUPT_DEBUG=1.
- 91/91 distro-safe regression suite green; F-09 byte sweep
  0/1827 silent accepts; F-06 HMAC fuzz 0/2000 silent accepts.
EOF

rpmbuild --define "_topdir $RPMROOT" \
         --define "_binary_payload w2.gzdio" \
         -bb "$RPMROOT/SPECS/$PKGNAME.spec" 2>&1 | tail -5

RPM_PATH=$(find "$RPMROOT/RPMS" -name "$PKGNAME-${VERSION}-*.rpm" | head -1)
if [ -n "$RPM_PATH" ]; then
    cp "$RPM_PATH" "/tmp/$PKGNAME-${VERSION}-${RELEASE}.${ARCH}.rpm"
    echo ""
    echo "Built: /tmp/$PKGNAME-${VERSION}-${RELEASE}.${ARCH}.rpm ($(du -h "/tmp/$PKGNAME-${VERSION}-${RELEASE}.${ARCH}.rpm" | cut -f1))"
    rpm -qpi "/tmp/$PKGNAME-${VERSION}-${RELEASE}.${ARCH}.rpm" 2>&1 | head -15
fi
