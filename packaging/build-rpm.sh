#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Build zupt RPM. Falls back to SRPM-equivalent tarball if rpmbuild absent.
set -e
cd "$(dirname "$0")/.."

VERSION="${VERSION:-2.2.2}"
RPMROOT="/tmp/rpmbuild-zupt"
rm -rf "$RPMROOT"
mkdir -p "$RPMROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

TMP="/tmp/zupt-$VERSION"
rm -rf "$TMP" && mkdir -p "$TMP"
cp -r include src tests jasmin doc vendor Makefile CMakeLists.txt \
      README.md CHANGELOG.md SECURITY.md AUDIT.md LICENSE "$TMP/" 2>/dev/null || true
tar -czf "$RPMROOT/SOURCES/zupt-$VERSION.tar.gz" -C /tmp "zupt-$VERSION"

cat > "$RPMROOT/SPECS/zupt.spec" <<EOF
Name:           zupt
Version:        $VERSION
Release:        1%{?dist}
Summary:        Post-quantum backup compression utility
License:        AGPL-3.0-or-later AND GPL-3.0-or-later
URL:            https://git.securityops.co/cristiancmoises/zupt
Source0:        zupt-%{version}.tar.gz

BuildRequires:  gcc make libargon2-devel openssl-devel >= 3.0 libzuptsdk-devel >= 2.0.0
Requires:       libargon2 openssl-libs >= 3.0 libzuptsdk2 >= 2.0.0

%description
Backup-oriented compression utility with hybrid post-quantum encryption
(ML-KEM-768 + X25519). Integrates libzuptsdk for state-of-the-art crypto:
HKDF combiner with domain separation, key commitment, HPKE binding,
anti-fault decapsulation, Argon2id password derivation.

%prep
%autosetup

%build
make %{?_smp_mflags}

%install
mkdir -p %{buildroot}%{_bindir}
install -m 755 zupt %{buildroot}%{_bindir}/zupt

%files
%license LICENSE
%doc README.md CHANGELOG.md SECURITY.md AUDIT.md
%{_bindir}/zupt

%changelog
* Mon Apr 27 2026 Cristian Cezar Moisés <zupt@riseup.net> - $VERSION-1
- Audit-driven release: 6 bugs fixed (varint truncation, unchecked fwrites,
  mac_key reuse, LZ length overflow, dedup ref recursion, partial archive
  cleanup on encrypt failure). 30/30 tests pass.
EOF

if command -v rpmbuild >/dev/null 2>&1; then
    rpmbuild --define "_topdir $RPMROOT" -bb "$RPMROOT/SPECS/zupt.spec" 2>&1 | tail -5
    cp "$RPMROOT/RPMS/x86_64/zupt-$VERSION-1."*.rpm /tmp/ 2>/dev/null || true
    ls /tmp/zupt-$VERSION-*.rpm 2>/dev/null
else
    SRPM_TAR="/tmp/zupt-$VERSION.srpm.tar.gz"
    tar -czf "$SRPM_TAR" -C "$RPMROOT" SPECS SOURCES
    echo "rpmbuild unavailable; SRPM-equivalent at: $SRPM_TAR"
    echo "Distros: tar -xzf $SRPM_TAR && rpmbuild -bb SPECS/zupt.spec"
fi
