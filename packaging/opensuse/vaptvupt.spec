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
Version:        4.0.0
Release:        0
Summary:        Post-quantum backup compression with AES-256 + ML-KEM-768 hybrid encryption
License:        AGPL-3.0-or-later
Group:          Productivity/Archiving/Compression
URL:            https://git.securityops.co/cristiancmoises/zupt
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
trademark on the name "Zupt") compresses and encrypts backup archives. LZ77+Huffman compression
(VaptVupt codec, ~2-3 GB/s decompression on x86_64 with AVX2 / aarch64
with NEON), AES-256-CTR + HMAC-SHA256 per-block authenticated
encryption, multi-threaded, with optional ML-KEM-768 + X25519
post-quantum hybrid key encapsulation (FIPS 203 + RFC 7748). The
default password KDF is Argon2id; PBKDF2-SHA256 remains available
via --kdf pbkdf2 for backward compatibility.

Pure C11, vendored libzuptsdk, ~5,000 lines of core code. Constant-
time cryptographic primitives are formally verified with Jasmin on
x86_64 (zupt_mac_verify_ct, zupt_ct_select_32); a clean C fallback
runs on aarch64 and other architectures.

%prep
%autosetup -p1
chmod +x tests/*.sh

%build
%make_build V=1 \
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
%make_build V=1 \
    CFLAGS="%{optflags} -fPIE -Wall -Wextra -std=c11 -Iinclude -Isrc" \
    LDFLAGS="%{?build_ldflags} -pie" \
    LDLIBS="-lm -lpthread" \
    test-vectors
./test_vectors
%else
%make_build V=1 \
    CFLAGS="%{optflags} -fPIE -Wall -Wextra -std=c11 -Iinclude -Isrc" \
    LDFLAGS="%{?build_ldflags} -pie" \
    LDLIBS="-lm -lpthread" \
    check
%endif

%install
%make_install PREFIX=%{_prefix}

%files
%license LICENSE
%doc README.md SECURITY.md CHANGELOG.md
%{_bindir}/vaptvupt
%{_bindir}/zupt
%{_mandir}/man1/vaptvupt.1%{?ext_man}
%{_mandir}/man1/zupt.1%{?ext_man}
%dir %{_prefix}/lib/vaptvupt
%{_prefix}/lib/vaptvupt/libzuptsdk.so
%{_prefix}/lib/vaptvupt/libzuptsdk.so.2
%{_prefix}/lib/vaptvupt/libzuptsdk.so.2.0.0
%{_prefix}/lib/vaptvupt/libpqvaptvupt.so
%{_prefix}/lib/vaptvupt/libpqvaptvupt.so.0
%{_prefix}/lib/vaptvupt/libpqvaptvupt.so.0.6.0

%changelog
