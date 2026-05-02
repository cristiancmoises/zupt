#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build self-contained zupt RPM. Bundles libzuptsdk.so.2 under
# /usr/lib/zupt/ so users do NOT need a separate libzuptsdk package.
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-2.2.3}"
ARCH="${ARCH:-x86_64}"
RELEASE="1"

SDK_LIB="vendor/zuptsdk/libzuptsdk.so.2.0.0"
if [ ! -f "$SDK_LIB" ]; then
    echo "ERROR: $SDK_LIB not found." >&2
    exit 1
fi

# Build zupt and patch RPATH to /usr/lib/zupt
echo "[rpm] Building zupt"
make clean >/dev/null 2>&1 || true
make -j"$(nproc)" >/dev/null
echo "[rpm] Patching rpath -> /usr/lib/zupt:/usr/lib64/zupt"
patchelf --set-rpath '/usr/lib/zupt:/usr/lib64/zupt' zupt
if ! readelf -d zupt | grep -q "RUNPATH.*\[/usr/lib/zupt:/usr/lib64/zupt\]"; then
    echo "ERROR: zupt does not have correct RUNPATH" >&2
    exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "[rpm] rpmbuild not found; falling back to packaging/build-rpm-manual.py"
    if [ ! -d "/tmp/zupt_${VERSION}_amd64" ]; then
        echo "[rpm] /tmp/zupt_${VERSION}_amd64 missing; running build-deb.sh first"
        bash packaging/build-deb.sh >/dev/null
    fi
    VERSION="$VERSION" python3 packaging/build-rpm-manual.py
    exit 0
fi

# Stage the source tarball that the spec's %install will unpack
RPMROOT="/tmp/rpmbuild-zupt"
rm -rf "$RPMROOT"
mkdir -p "$RPMROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

STAGE="/tmp/zupt-rpm-stage-${VERSION}"
rm -rf "$STAGE"
mkdir -p "$STAGE/zupt-${VERSION}"

cp zupt "$STAGE/zupt-${VERSION}/zupt"
cp "$SDK_LIB" "$STAGE/zupt-${VERSION}/libzuptsdk.so.2.0.0"
cp README.md CHANGELOG.md SECURITY.md AUDIT.md LICENSE "$STAGE/zupt-${VERSION}/"
[ -f doc/zupt.1 ] && cp doc/zupt.1 "$STAGE/zupt-${VERSION}/zupt.1"
tar -czf "$RPMROOT/SOURCES/zupt-${VERSION}.tar.gz" -C "$STAGE" "zupt-${VERSION}"

cat > "$RPMROOT/SPECS/zupt.spec" <<EOF
Name:           zupt
Version:        $VERSION
Release:        ${RELEASE}%{?dist}
Summary:        Post-quantum backup compression utility
License:        AGPL-3.0-or-later AND GPL-3.0-or-later
URL:            https://git.securityops.co/cristiancmoises/zupt
Source0:        zupt-%{version}.tar.gz

# libzuptsdk is bundled under /usr/lib/zupt; no external sdk dep needed.
Requires:       libargon2
Requires:       openssl-libs >= 3.0
AutoReqProv:    no

%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

%description
Backup-oriented compression utility with hybrid post-quantum encryption
(ML-KEM-768 + X25519). Provides AES-256-CTR + HMAC-SHA256 authenticated
encryption, multi-threaded compression, full-disk backup/restore,
block-level deduplication, and embeds the VaptVupt 2.48.2 codec for
high-throughput LZ77 + tANS compression with AVX2 and NEON SIMD
acceleration. The libzuptsdk shared library is bundled under
/usr/lib/zupt -- no separate package required.

%prep
%setup -q

%build
# Pre-built before rpmbuild was invoked; nothing to do.

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/zupt
mkdir -p %{buildroot}%{_docdir}/zupt
mkdir -p %{buildroot}%{_licensedir}/zupt
mkdir -p %{buildroot}%{_mandir}/man1

install -m 755 zupt %{buildroot}%{_bindir}/zupt
install -m 755 libzuptsdk.so.2.0.0 %{buildroot}%{_libdir}/zupt/libzuptsdk.so.2.0.0
ln -sf libzuptsdk.so.2.0.0 %{buildroot}%{_libdir}/zupt/libzuptsdk.so.2
ln -sf libzuptsdk.so.2.0.0 %{buildroot}%{_libdir}/zupt/libzuptsdk.so

install -m 644 README.md CHANGELOG.md SECURITY.md AUDIT.md %{buildroot}%{_docdir}/zupt/
install -m 644 LICENSE %{buildroot}%{_licensedir}/zupt/

if [ -f zupt.1 ]; then
    install -m 644 zupt.1 %{buildroot}%{_mandir}/man1/zupt.1
    gzip -9n %{buildroot}%{_mandir}/man1/zupt.1
fi

%files
%license %{_licensedir}/zupt/LICENSE
%doc %{_docdir}/zupt/README.md
%doc %{_docdir}/zupt/CHANGELOG.md
%doc %{_docdir}/zupt/SECURITY.md
%doc %{_docdir}/zupt/AUDIT.md
%{_bindir}/zupt
%dir %{_libdir}/zupt
%{_libdir}/zupt/libzuptsdk.so
%{_libdir}/zupt/libzuptsdk.so.2
%{_libdir}/zupt/libzuptsdk.so.2.0.0
%{_mandir}/man1/zupt.1.gz

%changelog
* Sat May 02 2026 Cristian Cezar Moises <zupt@riseup.net> - $VERSION-$RELEASE
- VaptVupt 2.48.2 codec integration (cost-aware lazy parser, format_v2
  flag, 4-stream Huffman literal coding, encoder memory hygiene).
- Wrapper defaults: checksum=0 (Zupt outer MAC authenticates),
  format_v2=1 for BALANCED/EXTREME (defensive guard against the
  upstream-untested format_v2 + ULTRA_FAST combination).
- Makefile arch-detection bug fixed (x86-64 / x86_64 mismatch).
- 22/22 regression tests, 14/14 threaded, 10/10 PQ, 11/11 VaptVupt,
  13/13 NIST vectors. ASAN clean across plain/password/PQ-SDK at
  levels 1, 5, 9.
EOF

rpmbuild --define "_topdir $RPMROOT" \
         --define "_binary_payload w2.gzdio" \
         -bb "$RPMROOT/SPECS/zupt.spec" 2>&1 | tail -8

RPM_PATH=$(find "$RPMROOT/RPMS" -name "zupt-${VERSION}-*.rpm" | head -1)
if [ -n "$RPM_PATH" ]; then
    cp "$RPM_PATH" "/tmp/zupt-${VERSION}-${RELEASE}.${ARCH}.rpm"
    echo ""
    echo "Built: /tmp/zupt-${VERSION}-${RELEASE}.${ARCH}.rpm ($(du -h /tmp/zupt-${VERSION}-${RELEASE}.${ARCH}.rpm | cut -f1))"
    rpm -qpi "/tmp/zupt-${VERSION}-${RELEASE}.${ARCH}.rpm" 2>&1 | head -15
fi
