# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Fedora / RHEL / CentOS RPM spec for vaptvupt.
#
# Build with:
#   spectool -g vaptvupt.spec               # fetches the upstream tarball
#   rpmbuild -ba vaptvupt.spec              # builds source + binary RPMs
#
# To bring a release into production:
#   1. Run `make dist` upstream → /tmp/vaptvupt-VERSION.tar.gz (reproducible).
#   2. Upload to a stable release URL (git.securityops.co releases).
#   3. Update %{version} below.
#   4. Run `sha256sum /tmp/vaptvupt-VERSION.tar.gz` and update Source0
#      checksum (handled by spectool when configured) or pin via
#      sha256sum in a separate manifest if your distro requires it.
#   5. rpmbuild --define '_topdir ~/rpmbuild' -ba zupt.spec
#
# This spec is written for Fedora 38+ and EPEL 9+; it should also work
# on RHEL 8 (with EPEL) by adjusting BuildRequires if Python 3.8+ isn't
# in the base.

Name:           vaptvupt
Version:        4.1.0
Release:        1%{?dist}
Summary:        Post-quantum backup compression utility (AES-256 + ML-KEM-768 + Argon2id, formerly Zupt)

License:        AGPL-3.0-or-later AND GPL-3.0-or-later
URL:            https://git.securityops.co/cristiancmoises/vaptvupt
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}.tar.gz

# v3.0.0: legacy `zupt` package is superseded. Renaming was forced
# by a prior INPI Brasil trademark registration on "Zupt". The
# archive extension (.zupt), wire format, magic bytes, and C ABI
# are unchanged.
Provides:       zupt = %{version}-%{release}
Obsoletes:      zupt < 3.0.0
Conflicts:      zupt < 3.0.0

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  glibc-devel
BuildRequires:  python3 >= 3.8
# python3 is only needed for the regression-test harness (byte sweeps,
# tamper injection). The shipped binary has no Python dependency.

Requires:       glibc

%description
Zupt is a pure-C11 backup compression utility featuring:

  * Post-quantum hybrid encryption (ML-KEM-768 + X25519, FIPS 203)
  * AES-256-CTR + HMAC-SHA256 authenticated encryption (Encrypt-then-MAC)
  * Argon2id password-based key derivation (default since 2.4.1)
  * Multi-threaded compression with the VaptVupt LZ codec
  * Full-disk backup and restore with sparse-region detection
  * End-to-end byte-level tamper detection on encrypted archives
    (0 silent-accept positions in the v1.6 exhaustive byte sweep)
  * Constant-time cryptographic primitives verified with Jasmin
  * NIST/RFC test vectors for SHA-256, SHA-3, ML-KEM-768, AES-256-CTR,
    HMAC-SHA256, X25519, PBKDF2, Argon2id

The archive format includes an integrity trailer that authenticates
the header and footer, per-block HMAC with bound frame-preface AAD,
and optional encrypted comments.

%global debug_package %{nil}
# Single source RPM, no -debuginfo split for the initial release.

%prep
%autosetup -n %{name}-%{version}

%build
# Use Fedora's default optflags but with the project's preferred warning set.
CFLAGS="%{optflags} -Wall -Wextra -Wpedantic -std=c11" \
LDFLAGS="%{?build_ldflags}" \
%make_build

%check
# Run the upstream regression suite. F-06 HMAC trials, F-08 top-MAC sweep,
# F-09 byte sweep (1827 positions), F-10..F-12 regressions, dist
# reproducibility. ~3 minutes on modern hardware.
%make_build test

%install
%make_install DESTDIR=%{buildroot} PREFIX=/usr

# Install the vendored libzuptsdk into /usr/lib/zupt/ — the binary is
# linked with -Wl,-rpath,$ORIGIN/vendor/zuptsdk so we preserve the same
# layout under /usr/.
install -d %{buildroot}%{_libdir}/%{name}
install -m 0755 vendor/zuptsdk/libzuptsdk.so.2.0.0 \
    %{buildroot}%{_libdir}/%{name}/libzuptsdk.so.2.0.0
ln -sf libzuptsdk.so.2.0.0 %{buildroot}%{_libdir}/%{name}/libzuptsdk.so.2
ln -sf libzuptsdk.so.2.0.0 %{buildroot}%{_libdir}/%{name}/libzuptsdk.so
install -m 0755 vendor/pqvaptvupt/libpqvaptvupt.so.0.6.0 \
    %{buildroot}%{_libdir}/%{name}/libpqvaptvupt.so.0.6.0
ln -sf libpqvaptvupt.so.0.6.0 %{buildroot}%{_libdir}/%{name}/libpqvaptvupt.so.0
ln -sf libpqvaptvupt.so.0.6.0 %{buildroot}%{_libdir}/%{name}/libpqvaptvupt.so

%files
%license LICENSE
%doc README.md SECURITY.md CHANGELOG.md
%{_bindir}/zupt
%{_libdir}/%{name}/libzuptsdk.so.2.0.0
%{_libdir}/%{name}/libzuptsdk.so.2
%{_libdir}/%{name}/libzuptsdk.so
%{_libdir}/%{name}/libpqvaptvupt.so.0.6.0
%{_libdir}/%{name}/libpqvaptvupt.so.0
%{_libdir}/%{name}/libpqvaptvupt.so
%if 0%{?_mandir:1}
%{_mandir}/man1/zupt.1*
%endif

%changelog
* Tue May 20 2025 Cristian Cezar Moisés <sac@securityops.co> - 2.4.4-1
- Initial Fedora/EPEL RPM package.
- Tracks upstream v2.4.4: distribution packaging release; archive
  format unchanged from v2.4.3 (v1.6, 0/1878 silent-accept byte
  tampers).
