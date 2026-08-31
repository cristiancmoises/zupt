# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Fedora / RHEL / CentOS RPM spec for zupt.
#
# Build with:
#   spectool -g zupt.spec                    # fetches the upstream tarball
#   rpmbuild -ba zupt.spec                   # builds source + binary RPMs
#
# To bring a release into production:
#   1. Run `make dist` upstream → /tmp/zupt-VERSION.tar.gz (reproducible).
#   2. Upload to the canonical GitHub release.
#   3. Update %{version} below.
#   4. Run `sha256sum /tmp/zupt-VERSION.tar.gz` and update Source0
#      checksum (handled by spectool when configured) or pin via
#      sha256sum in a separate manifest if your distro requires it.
#   5. rpmbuild --define '_topdir /path/to/rpmbuild' -ba zupt.spec
#
# This is an upstream Fedora-family recipe. A target is supported only after
# that exact distribution release and architecture have built and passed the
# installed smoke test.

Name:           zupt
Version:        5.2.4
Release:        1%{?dist}
Summary:        Backup compression with authenticated and post-quantum encryption

License:        AGPL-3.0-or-later AND GPL-3.0-or-later AND BSD-2-Clause AND BSD-3-Clause AND CC0-1.0
URL:            https://github.com/cristiancmoises/zupt
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  git-core
BuildRequires:  make
BuildRequires:  glibc-devel
BuildRequires:  python3 >= 3.8
BuildRequires:  bash
BuildRequires:  coreutils
BuildRequires:  diffutils
BuildRequires:  file
BuildRequires:  findutils
BuildRequires:  gawk
BuildRequires:  grep
BuildRequires:  gzip
BuildRequires:  sed
BuildRequires:  tar
# python3 is only needed for the regression-test harness (byte sweeps,
# tamper injection). The shipped binary has no Python dependency.

Provides:       bundled(vaptvupt-codec) = 2.65.3

%description
ZUPT is a pure-C11 backup compression utility featuring:

  * Post-quantum hybrid encryption (ML-KEM-768 + X25519) and full
    ML-KEM-768 mode (--pq-only)
  * AES-256-CTR + HMAC-SHA256 authenticated encryption (Encrypt-then-MAC)
  * PBKDF2-SHA256 password key derivation (Argon2id in WITH_SDK=1 builds)
  * Multi-threaded compression with the VaptVupt LZ + ANS codec
  * Full-disk backup and restore with sparse-region detection
  * Authenticated encrypted-archive metadata and per-block integrity checks
  * Portable C implementations with optional source-built assembly paths
  * NIST/RFC test vectors for SHA-256, SHA-3, ML-KEM-768, AES-256-CTR,
    HMAC-SHA256, X25519 and PBKDF2

Encrypted archives include an integrity trailer that authenticates the header
and footer, per-block HMAC with bound frame-preface AAD, and optional encrypted
comments. Plain archives use non-cryptographic checksums.

%prep
%autosetup -n %{name}-%{version}

%build
# Source-only build (WITH_SDK=0): no vendored libraries, no external crypto
# dependency. Fedora's default optflags plus the project's warning set.
%make_build V=1 WITH_SDK=0 WITH_PQBOX=0 \
    CFLAGS="%{optflags}" \
    LDFLAGS="%{?build_ldflags}"

%check
# Distro-safe quick, path-traversal, integrity, codec, HMAC and NIST/RFC
# checks. Full, optional-integration and dist-reproducibility suites remain
# release gates outside the package build.
%make_build V=1 WITH_SDK=0 WITH_PQBOX=0 \
    CFLAGS="%{optflags}" \
    LDFLAGS="%{?build_ldflags}" \
    check

%install
%make_install WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 INSTALL_LICENSES=0 \
    PREFIX=%{_prefix} BINDIR=%{_bindir} MANDIR=%{_mandir}

%files
%license LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0 NOTICE THIRD-PARTY-NOTICES.md
%doc README.md SECURITY.md THREAT_MODEL.md CHANGELOG.md
%{_bindir}/%{name}
%{_datadir}/bash-completion/completions/%{name}
%{_datadir}/zsh/site-functions/_%{name}
%{_datadir}/fish/vendor_completions.d/%{name}.fish
%if 0%{?_mandir:1}
%{_mandir}/man1/%{name}.1*
%endif

%changelog
* Mon Aug 31 2026 Cristian Cezar Moisés <sac@securityops.co> - 5.2.4-1
- Make the static Windows GUI package-version check robust to canonical CRLF
  checkouts, advance source-only package metadata, and prepare final hashes.

* Mon Aug 31 2026 Cristian Cezar Moisés <sac@securityops.co> - 5.2.3-1
- Correct the release-package CI version checks and portable GUI version
  contract, and make the openSUSE container replace busybox-gawk before
  installing the native RPM toolchain.

* Mon Aug 31 2026 Cristian Cezar Moisés <sac@securityops.co> - 5.2.2-1
- Source-only release; optional SDK/PQBOX integrations use system development
  packages only and are disabled for this package.
- Preserve distribution flags and debuginfo, remove RPATH/vendor-library
  fallbacks, run the real upstream check target, and restore the zupt command.

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
