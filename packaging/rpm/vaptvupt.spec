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
Version:        5.2.1
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

  * Post-quantum hybrid encryption (ML-KEM-768 + X25519, FIPS 203,
    validated byte-for-byte against OpenSSL's ML-KEM-768) and full
    pure ML-KEM-768 (--pq-only)
  * AES-256-CTR + HMAC-SHA256 authenticated encryption (Encrypt-then-MAC)
  * PBKDF2-SHA256 password key derivation (Argon2id in WITH_SDK=1 builds)
  * Multi-threaded compression with the VaptVupt LZ + ANS codec
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
# Source-only build (WITH_SDK=0): no vendored libraries, no external crypto
# dependency. Fedora's default optflags plus the project's warning set.
%make_build WITH_SDK=0 \
    CFLAGS="%{optflags} -fPIE -Wall -Wextra -std=c11 -Iinclude -Isrc" \
    LDFLAGS="%{?build_ldflags} -pie" \
    LDLIBS="-lm -lpthread"

%check
# Distro-safe regression subset: F-06 HMAC trials, F-08 top-MAC sweep,
# F-09 byte sweep, F-10..F-12 regressions, the dedup-nonce regression,
# and NIST/RFC vectors. Skips threaded/dist-reproducibility tests that
# are sensitive to the build host.
%make_build WITH_SDK=0 \
    CFLAGS="%{optflags} -fPIE -Wall -Wextra -std=c11 -Iinclude -Isrc" \
    LDFLAGS="%{?build_ldflags} -pie" \
    LDLIBS="-lm -lpthread" \
    check

%install
%make_install WITH_SDK=0 DESTDIR=%{buildroot} PREFIX=/usr

%files
%license LICENSE
%doc README.md SECURITY.md CHANGELOG.md
%{_bindir}/%{name}
%{_bindir}/zupt
%{_datadir}/bash-completion/completions/%{name}
%{_datadir}/bash-completion/completions/zupt
%{_datadir}/zsh/site-functions/_%{name}
%{_datadir}/zsh/site-functions/_zupt
%{_datadir}/fish/vendor_completions.d/%{name}.fish
%if 0%{?_mandir:1}
%{_mandir}/man1/%{name}.1*
%{_mandir}/man1/zupt.1*
%endif

%changelog
* Sat Jul 11 2026 Cristian Cezar Moisés <sac@securityops.co> - 5.1.0-1
- Codec 2.65.0; large compression-ratio gains (auto format_v2 + level-scaled
  block window); --dedup keeps a small block; GUI compress-hang and
  job-completion-crash fixes. Wire format unchanged (v1.6).

* Fri Jul 10 2026 Cristian Cezar Moisés <sac@securityops.co> - 5.0.0-1
- ML-KEM-768 is now genuinely FIPS 203-conformant (was round-3 CRYSTALS-Kyber):
  fixed a transposed matrix-A sampling convention, the round-3 KDF, and the
  implicit-rejection domain. Validated byte-for-byte against OpenSSL 3.5's
  FIPS 203 ML-KEM-768 (tests/test_mlkem_fips203.sh, run in %%check).
- BREAKING: --pq / --pq-only keys and archives from <= 4.2.1 no longer decrypt.
  Regenerate keys and re-encrypt. Password mode / plain compression unaffected.
- Security: compress data-loss + silent-plaintext guards; AVX2 decoder heap
  OOB-read bound; overflow-safe solid-mode test path; secret-wipe on error.
- GUI reworked for the source-only build; truthful banner/help.

* Fri Jul 10 2026 Cristian Cezar Moisés <sac@securityops.co> - 4.2.1-1
- Fix: "vaptvupt info" mislabelled full post-quantum (--pq-only) archives as
  "PQ Hybrid (ML-KEM-768 + X25519)". info now reads the real enc_type from the
  encryption-header block and reports the actual mode ("ML-KEM-768 only, no
  classical layer" for --pq-only). Reader-side only; no wire-format change.

* Thu Jul 09 2026 Cristian Cezar Moisés <sac@securityops.co> - 4.2.0-1
- New native full (pure) post-quantum mode --pq-only: ML-KEM-768 as the
  sole KEM, no classical X25519 (envelope 0x06). For "PQ-only" compliance
  postures; hybrid --pq remains the recommended default. In-tree crypto.
- Security (critical): fixed AES-256-CTR keystream reuse under --dedup
  (every block now uses a fresh random 128-bit nonce). Re-encrypt any
  --dedup encrypted archives written by <= 4.1.0.
- Clearer keygen --sdk/--box guidance on source-only builds.
- Wire format v1.6 unchanged.

* Tue May 20 2025 Cristian Cezar Moisés <sac@securityops.co> - 2.4.4-1
- Initial Fedora/EPEL RPM package.
- Tracks upstream v2.4.4: distribution packaging release; archive
  format unchanged from v2.4.3 (v1.6, 0/1878 silent-accept byte
  tampers).
