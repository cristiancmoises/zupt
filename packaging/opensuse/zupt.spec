#
# spec file for package zupt
#
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SUSE LLC
# Copyright (c) 2026 Alessandro de Oliveira Faria (A.K.A. Cabelo) <cabelo@opensuse.org>
# Alessandro's attribution is for downstream openSUSE/OBS packaging only.
# Copyright (c) 2025-2026 Cristian Cezar Moisés <sac@securityops.co> (upstream)
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.
#

Name:           zupt
Version:        5.2.4
Release:        0
Summary:        Backup compression with authenticated and post-quantum encryption
License:        AGPL-3.0-or-later AND GPL-3.0-or-later AND BSD-2-Clause AND BSD-3-Clause AND CC0-1.0
URL:            https://github.com/cristiancmoises/zupt
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  bash
BuildRequires:  coreutils
BuildRequires:  diffutils
BuildRequires:  file
BuildRequires:  findutils
BuildRequires:  gawk
BuildRequires:  gcc
BuildRequires:  git-core
BuildRequires:  grep
BuildRequires:  gzip
BuildRequires:  make
BuildRequires:  python3-base
BuildRequires:  sed
BuildRequires:  tar
Provides:       bundled(vaptvupt-codec) = 2.65.3
Provides:       vaptvupt = %{version}-%{release}
Obsoletes:      vaptvupt < %{version}

%description
ZUPT creates compressed backup archives with optional authenticated
password encryption or ML-KEM-768 and X25519 hybrid key encapsulation. The
default package is built entirely from the source in the release archive.

Optional SDK and PQBOX features are disabled because audited development
packages are unavailable. No private compiled library is installed.

%prep
%autosetup -p1
bash scripts/check-source-only.sh --tree .

%build
%make_build WITH_SDK=0 WITH_PQBOX=0 \
    CFLAGS="%{optflags} -fPIE" \
    LDFLAGS="%{?build_ldflags} -Wl,-z,relro,-z,now -pie"

%check
%make_build WITH_SDK=0 WITH_PQBOX=0 \
    CFLAGS="%{optflags} -fPIE" \
    LDFLAGS="%{?build_ldflags} -Wl,-z,relro,-z,now -pie" \
    check

%install
%make_install WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 INSTALL_LICENSES=0 \
    PREFIX=%{_prefix} \
    BINDIR=%{_bindir} \
    MANDIR=%{_mandir}

%files
%license LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0 NOTICE THIRD-PARTY-NOTICES.md
%doc README.md CHANGELOG.md SECURITY.md THREAT_MODEL.md
%{_bindir}/zupt
%{_datadir}/bash-completion/completions/zupt
%{_datadir}/zsh/site-functions/_zupt
%{_datadir}/fish/vendor_completions.d/zupt.fish
%{_mandir}/man1/zupt.1%{?ext_man}

%changelog
