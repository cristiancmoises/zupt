#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

# Build a real noarch RPM and source RPM. Run this in a native RPM build
# environment; there is deliberately no --nodeps or tarball fallback.

set -Eeuo pipefail
umask 022
export LC_ALL=C

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"
header_version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' include/zupt.h)
version=${VERSION:-$header_version}
[[ $version == "$header_version" && $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
    die "VERSION '$version' does not match include/zupt.h '$header_version'"

dist_dir=${DIST_DIR:-${TMPDIR:-/tmp}/zupt-release}
mkdir -p -- "$dist_dir"
dist_dir=$(cd -- "$dist_dir" && pwd -P)
case $dist_dir/ in "$repo_root"/*) die 'DIST_DIR must be outside the repository' ;; esac

for command_name in make python3 rpmbuild rpm rpm2cpio cpio tar sha256sum; do
    command -v -- "$command_name" >/dev/null 2>&1 || \
        die "required command not found: $command_name"
done

jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-gui-rpm.XXXXXXXX")
top=$work/rpmbuild
tree=$work/zupt-gui-$version
extract=$work/extract
mkdir -p -- "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} \
    "$tree"/{src,assets,doc} "$extract"
cleanup() {
    make -C "$repo_root" clean >/dev/null 2>&1 || true
    chmod -R u+rwX "$work" 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

printf '[GUI rpm] validating source-only CLI dependency %s\n' "$version"
make clean
make -j"$jobs" V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0
make V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 check
./zupt version | grep -Fq "zupt $version" || die 'CLI version check failed'

install -m 0644 gui/src/zupt_gui.py "$tree/src/"
install -m 0644 gui/assets/zupt-icon.png "$tree/assets/"
install -m 0644 gui/packaging/zupt-gui.desktop "$tree/"
install -m 0644 doc/zupt-gui.1 "$tree/doc/"
install -m 0644 gui/README.md "$tree/README.md"
install -m 0644 LICENSE LICENSE-AGPL-3.0 "$tree/"
install -m 0644 gui/LICENSE-GUI "$tree/LICENSE-GUI"
install -m 0644 gui/assets/README.md "$tree/ASSET-PROVENANCE.md"

source_epoch=${SOURCE_DATE_EPOCH:-$(sed -n '1p' .source-date-epoch 2>/dev/null || true)}
[[ $source_epoch =~ ^[0-9]+$ ]] || die 'SOURCE_DATE_EPOCH is not available'
source_tar=$top/SOURCES/zupt-gui-$version.tar.gz
tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
    -czf "$source_tar" -C "$work" "zupt-gui-$version"

cat >"$top/SPECS/zupt-gui.spec" <<EOF
Name:           zupt-gui
Version:        $version
Release:        1
Summary:        Qt graphical interface for the ZUPT backup utility
License:        AGPL-3.0-or-later
URL:            https://github.com/cristiancmoises/zupt
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  python3 >= 3.9
Requires:       python3 >= 3.9
Requires:       (python3-qt6 or python3-pyside6 or python3-pyqt6)
Requires:       zupt >= %{version}

%description
ZUPT GUI creates, inspects, verifies, and extracts .zupt archives through
the separately packaged zupt command. Optional SDK and PQ-box controls are
shown only when that command reports the corresponding integration enabled.

%prep
%autosetup

%build

%check
python3 -c 'from pathlib import Path; p=Path("src/zupt_gui.py"); compile(p.read_text(encoding="utf-8"), str(p), "exec")'

%install
install -Dm0644 src/zupt_gui.py %{buildroot}%{_datadir}/zupt-gui/zupt_gui.py
install -Dm0644 zupt-gui.desktop %{buildroot}%{_datadir}/applications/zupt-gui.desktop
install -Dm0644 assets/zupt-icon.png %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/zupt-gui.png
install -Dm0644 doc/zupt-gui.1 %{buildroot}%{_mandir}/man1/zupt-gui.1
mkdir -p %{buildroot}%{_bindir}
cat >%{buildroot}%{_bindir}/zupt-gui <<'WRAP'
#!/bin/sh
exec python3 %{_datadir}/zupt-gui/zupt_gui.py "\$@"
WRAP
chmod 0755 %{buildroot}%{_bindir}/zupt-gui

%files
%license LICENSE LICENSE-AGPL-3.0 LICENSE-GUI
%doc README.md ASSET-PROVENANCE.md
%{_bindir}/zupt-gui
%{_datadir}/zupt-gui/zupt_gui.py
%{_datadir}/applications/zupt-gui.desktop
%{_datadir}/icons/hicolor/256x256/apps/zupt-gui.png
%{_mandir}/man1/zupt-gui.1*

%changelog
* Mon Aug 31 2026 Cristian Cezar Moisés <sac@securityops.co> - $version-1
- Package the integrated GUI under its restored ZUPT identity.
- Require the separately built source-only baseline CLI package.
EOF

rpmbuild --define "_topdir $top" -ba "$top/SPECS/zupt-gui.spec"

mapfile -t main_rpms < <(find "$top/RPMS" -type f -name "zupt-gui-$version-*.noarch.rpm" -print | sort)
mapfile -t source_rpms < <(find "$top/SRPMS" -type f -name "zupt-gui-$version-*.src.rpm" -print | sort)
[[ ${#main_rpms[@]} -eq 1 ]] || die "expected one GUI RPM, found ${#main_rpms[@]}"
[[ ${#source_rpms[@]} -eq 1 ]] || die "expected one GUI source RPM, found ${#source_rpms[@]}"

main_rpm=${main_rpms[0]}
source_rpm=${source_rpms[0]}
[[ $(rpm -qp --qf '%{NAME}' "$main_rpm") == zupt-gui ]] || \
    die 'GUI binary RPM name metadata is not zupt-gui'
[[ $(rpm -qp --qf '%{VERSION}' "$main_rpm") == "$version" ]] || \
    die 'GUI binary RPM version metadata does not match the release'
[[ $(rpm -qp --qf '%{RELEASE}' "$main_rpm") == 1 ]] || \
    die 'GUI binary RPM release metadata is not 1'
[[ $(rpm -qp --qf '%{SOURCEPACKAGE}' "$main_rpm") == '(none)' ]] || \
    die 'GUI binary RPM is marked as a source package'
[[ $(rpm -qp --qf '%{SOURCERPM}' "$main_rpm") == "$(basename -- "$source_rpm")" ]] || \
    die 'GUI binary RPM does not reference the matching source RPM'
[[ $(rpm -qp --qf '%{NAME}' "$source_rpm") == zupt-gui ]] || \
    die 'GUI source RPM name metadata is not zupt-gui'
[[ $(rpm -qp --qf '%{VERSION}' "$source_rpm") == "$version" ]] || \
    die 'GUI source RPM version metadata does not match the release'
[[ $(rpm -qp --qf '%{RELEASE}' "$source_rpm") == 1 ]] || \
    die 'GUI source RPM release metadata is not 1'
[[ $(rpm -qp --qf '%{SOURCEPACKAGE}' "$source_rpm") == 1 ]] || \
    die 'GUI source RPM is not marked as a source package'
[[ $(rpm -qp --qf '%{SOURCERPM}' "$source_rpm") == '(none)' ]] || \
    die 'GUI source RPM unexpectedly references another source RPM'
mapfile -t source_members < <(rpm -qpl "$source_rpm" | sort)
expected_source_members=("zupt-gui-${version}.tar.gz" zupt-gui.spec)
mapfile -t expected_source_members < <(printf '%s\n' "${expected_source_members[@]}" | sort)
[[ ${#source_members[@]} -eq 2 && \
    ${source_members[*]} == "${expected_source_members[*]}" ]] || \
    die 'GUI source RPM payload is not the exact Source0/spec pair'

rpm -qpl "$main_rpm" >"$work/contents.txt"
grep -q '^/usr/bin/zupt-gui$' "$work/contents.txt" || die 'GUI launcher missing from RPM'
if grep -Eq '(^/usr/bin/vaptvupt-gui$|\.(o|obj|a|so|so\.[^/]+|dll|dylib|exe)$)' "$work/contents.txt"; then
    cat "$work/contents.txt" >&2
    die 'forbidden compatibility alias or compiled artifact in GUI RPM'
fi
(cd -- "$extract" && rpm2cpio "$main_rpm" | cpio -idm --quiet)
PYTHONDONTWRITEBYTECODE=1 python3 - <<PY
from pathlib import Path
p = Path("$extract/usr/share/zupt-gui/zupt_gui.py")
compile(p.read_text(encoding="utf-8"), str(p), "exec")
PY

for artifact in "$main_rpm" "$source_rpm"; do
    destination=$dist_dir/$(basename -- "$artifact")
    [[ ! -e $destination ]] || die "refusing to overwrite existing output: $destination"
    cp -- "$artifact" "$destination"
    sha256sum "$destination"
done
printf 'PASS: built and content-validated GUI RPM and source RPM in %s\n' "$dist_dir"
