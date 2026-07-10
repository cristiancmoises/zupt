#
# spec file for package vaptvupt
#
# Copyright (c) 2026 SUSE LLC
# Copyright (c) 2026 Alessandro de Oliveira Faria (A.K.A CABELO) <cabelo@opensuse.org>
# Copyright (c) 2025-2026 Cristian Cezar Moisés <zupt@riseup.net> (upstream)
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


Name:           vaptvupt
Version:        4.2.1
Release:        0
Summary:        Post-quantum backup compression with AES-256 + ML-KEM-768 hybrid encryption
License:        AGPL-3.0-or-later
Group:          Productivity/Archiving/Compression
URL:            https://git.securityops.co/cristiancmoises/vaptvupt
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  gcc
BuildRequires:  gzip
BuildRequires:  make

# v3.0.0 renamed the project Zupt -> VaptVupt (prior INPI Brasil
# trademark on "Zupt"). Cleanly supersede any installed zupt package;
# the binary still installs a /usr/bin/zupt compatibility symlink.
Provides:       zupt = %{version}-%{release}
Obsoletes:      zupt < 3.0.0

%description
VaptVupt (formerly Zupt; renamed in v3.0.0 due to a prior INPI Brasil
trademark on the name "Zupt") compresses and encrypts backup archives.
LZ + ANS compression (VaptVupt codec, ~2-3 GB/s decompression on x86_64
with AVX2 / aarch64 with NEON), AES-256-CTR + HMAC-SHA256 per-block
authenticated encryption, multi-threaded, with ML-KEM-768 + X25519
post-quantum hybrid key encapsulation (FIPS 203 + RFC 7748) via --pq.

This package builds entirely from source with no external library
dependency. The password KDF is PBKDF2-SHA256 (600k iterations). The
optional libzuptsdk-backed modes (Argon2id KDF, --pq-sdk, --pq-box) are
not built here; they require an upstream WITH_SDK=1 build against the
separately distributed libzuptsdk/libpqvaptvupt.

Pure C11, ~5,000 lines of core code. Constant-time cryptographic
primitives are formally verified with Jasmin on x86_64
(zupt_mac_verify_ct, zupt_ct_select_32); a clean C fallback runs on
aarch64 and other architectures.

%prep
%autosetup -p1
chmod +x tests/*.sh

%build
%make_build V=1 WITH_SDK=0 \
    CFLAGS="%{optflags} -fPIE -Wall -Wextra -std=c11 -Iinclude -Isrc" \
    LDFLAGS="%{?build_ldflags} -pie" \
    LDLIBS="-lm -lpthread"

%check
# `make check` is the distro-safe subset added in 2.4.8: runs the
# security-critical regressions (F-06 HMAC, F-08 AIT, F-09 byte
# integrity, F-10 KDF, F-11 auth-fail, F-12 comments) plus NIST/RFC
# vectors. Skips threaded and dist-reproducibility tests that are
# sensitive to build-host environment.
#
# On s390x, fall back to just the vector tests (Jasmin assembly is
# x86_64-only; threading harness has been flaky on big-endian).
%ifarch s390x
%make_build V=1 WITH_SDK=0 \
    CFLAGS="%{optflags} -fPIE -Wall -Wextra -std=c11 -Iinclude -Isrc" \
    LDFLAGS="%{?build_ldflags} -pie" \
    LDLIBS="-lm -lpthread" \
    test-vectors
./test_vectors
%else
%make_build V=1 WITH_SDK=0 \
    CFLAGS="%{optflags} -fPIE -Wall -Wextra -std=c11 -Iinclude -Isrc" \
    LDFLAGS="%{?build_ldflags} -pie" \
    LDLIBS="-lm -lpthread" \
    check
%endif

%install
%make_install WITH_SDK=0 PREFIX=%{_prefix}

%files
%license LICENSE
%doc README.md SECURITY.md CHANGELOG.md
%{_bindir}/vaptvupt
%{_bindir}/zupt
%{_datadir}/bash-completion/completions/vaptvupt
%{_datadir}/bash-completion/completions/zupt
%{_datadir}/zsh/site-functions/_vaptvupt
%{_datadir}/zsh/site-functions/_zupt
%{_datadir}/fish/vendor_completions.d/vaptvupt.fish
%{_mandir}/man1/vaptvupt.1%{?ext_man}
%{_mandir}/man1/zupt.1%{?ext_man}

%changelog
