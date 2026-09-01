#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

set -Eeuo pipefail

umask 022
export LC_ALL=C

die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

header_version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' include/zupt.h)
version=${VERSION:-$header_version}
[[ -n $version && $version == "$header_version" ]] || \
    die "VERSION '$version' does not match include/zupt.h '$header_version'"
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid package version: $version"

spec=packaging/opensuse/zupt.spec
[[ -f $spec ]] || die "spec file not found: $spec"
spec_version=$(sed -n 's/^Version:[[:space:]]*//p' "$spec" | head -n 1)
[[ $spec_version == "$version" ]] || die "spec version '$spec_version' does not match '$version'"

dist_dir=${DIST_DIR:-${TMPDIR:-/tmp}/zupt-release}
mkdir -p -- "$dist_dir"
dist_dir=$(cd -- "$dist_dir" && pwd -P)

for command_name in make git rpmbuild rpm rpm2cpio cpio date readelf sha256sum tar; do
    command -v -- "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-rpm.XXXXXXXX")
top=$work/rpmbuild
extract=$work/extract
mkdir -p -- "$top/BUILD" "$top/BUILDROOT" "$top/RPMS" "$top/SOURCES" \
    "$top/SPECS" "$top/SRPMS" "$extract"

cleanup() {
    chmod -R u+rwX "$work" 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

source_tar=$top/SOURCES/zupt-${version}.tar.gz
printf '[rpm] creating audited source archive for ZUPT %s\n' "$version"
make DIST_TARBALL="$source_tar" WITH_SDK=0 WITH_PQBOX=0 dist
archive_version=$(tar -xOf "$source_tar" "zupt-${version}/include/zupt.h" | \
    sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p')
[[ $archive_version == "$version" ]] || die "source archive version is '$archive_version', expected '$version'"

install -m 0644 "$spec" "$top/SPECS/zupt.spec"
# OBS converts zupt.changes into RPM changelog metadata.  Standalone
# rpmbuild does not, so add an equivalent release entry only to the temporary
# spec used for this release artifact.
changelog_sections=$(grep -Ec '^%changelog[[:space:]]*$' "$top/SPECS/zupt.spec" || true)
[[ $changelog_sections -eq 1 ]] || \
    die "expected exactly one %changelog section, found $changelog_sections"
source_epoch=${SOURCE_DATE_EPOCH:-$(sed -n '1p' .source-date-epoch 2>/dev/null || true)}
[[ $source_epoch =~ ^[0-9]+$ ]] || die 'SOURCE_DATE_EPOCH is not available'
changelog_date=$(date -u --date="@$source_epoch" '+%a %b %d %Y')
cat >> "$top/SPECS/zupt.spec" <<EOF

* $changelog_date Cristian Cezar Moisés <sac@securityops.co> - $version-0
- Build the release package from audited source with optional SDK and PQBOX
  features disabled.
EOF
rpmbuild --define "_topdir $top" -ba "$top/SPECS/zupt.spec"

mapfile -t main_rpms < <(find "$top/RPMS" -type f -name "zupt-${version}-*.rpm" \
    ! -name '*-debuginfo-*' ! -name '*-debugsource-*' -print | sort)
[[ ${#main_rpms[@]} -eq 1 ]] || die "expected one main RPM, found ${#main_rpms[@]}"
main_rpm=${main_rpms[0]}

mapfile -t source_rpms < <(find "$top/SRPMS" -type f -name "zupt-${version}-*.src.rpm" -print | sort)
[[ ${#source_rpms[@]} -eq 1 ]] || die "expected one source RPM, found ${#source_rpms[@]}"
source_rpm=${source_rpms[0]}

[[ $(rpm -qp --qf '%{NAME}' "$main_rpm") == zupt ]] || \
    die 'binary RPM name metadata is not zupt'
[[ $(rpm -qp --qf '%{VERSION}' "$main_rpm") == "$version" ]] || \
    die 'binary RPM version metadata does not match the release'
[[ $(rpm -qp --qf '%{SOURCEPACKAGE}' "$main_rpm") == '(none)' ]] || \
    die 'binary RPM is marked as a source package'
[[ $(rpm -qp --qf '%{SOURCERPM}' "$main_rpm") == "$(basename -- "$source_rpm")" ]] || \
    die 'binary RPM does not reference the matching source RPM'
[[ $(rpm -qp --qf '%{NAME}' "$source_rpm") == zupt ]] || \
    die 'source RPM name metadata is not zupt'
[[ $(rpm -qp --qf '%{VERSION}' "$source_rpm") == "$version" ]] || \
    die 'source RPM version metadata does not match the release'
[[ $(rpm -qp --qf '%{SOURCEPACKAGE}' "$source_rpm") == 1 ]] || \
    die 'source RPM is not marked as a source package'
[[ $(rpm -qp --qf '%{SOURCERPM}' "$source_rpm") == '(none)' ]] || \
    die 'source RPM unexpectedly references another source RPM'
mapfile -t source_members < <(rpm -qpl "$source_rpm" | sort)
expected_source_members=("zupt-${version}.tar.gz" zupt.spec)
mapfile -t expected_source_members < <(printf '%s\n' "${expected_source_members[@]}" | sort)
[[ ${#source_members[@]} -eq 2 && \
    ${source_members[*]} == "${expected_source_members[*]}" ]] || \
    die 'source RPM payload is not the exact Source0/spec pair'

rpm -qpi "$main_rpm" >/dev/null
rpm -qpl "$main_rpm" > "$work/contents.txt"
if grep -Eq '(^/usr/bin/vaptvupt$|\.(o|obj|a|so|so\.[^/]+|dll|dylib)$)' "$work/contents.txt"; then
    cat "$work/contents.txt" >&2
    die 'forbidden alias or compiled library/object found in RPM contents'
fi
if grep -q '^/usr/local/' "$work/contents.txt"; then
    cat "$work/contents.txt" >&2
    die 'RPM contains files below /usr/local'
fi

(cd -- "$extract" && rpm2cpio "$main_rpm" | cpio -idm --quiet)
binary=$extract/usr/bin/zupt
[[ -x $binary ]] || die 'RPM does not contain executable /usr/bin/zupt'
if ! readelf -h "$binary" 2>/dev/null | grep -Eq 'Type:[[:space:]]+DYN'; then
    die 'RPM executable is not a position-independent executable (PIE)'
fi
if ! readelf -W -l "$binary" 2>/dev/null | grep -q 'GNU_RELRO'; then
    die 'RPM executable lacks a GNU_RELRO segment'
fi
stack_segment=$(readelf -W -l "$binary" 2>/dev/null | grep 'GNU_STACK' || true)
[[ -n $stack_segment && $stack_segment != *RWE* ]] || \
    die 'RPM executable has a missing or executable GNU_STACK segment'
if readelf -d "$binary" 2>/dev/null | grep -Eq '(RPATH|RUNPATH)'; then
    readelf -d "$binary" | grep -E '(RPATH|RUNPATH)' >&2
    die 'RPM executable contains RPATH/RUNPATH'
fi
if readelf -d "$binary" 2>/dev/null | grep -Eqi '(vendor/|libvuptsdk|libpqvaptvupt)'; then
    die 'RPM executable references a vendored optional library'
fi
bash scripts/test-installed-zupt.sh "$binary"

artifacts=("$main_rpm" "$source_rpm")
for artifact in "${artifacts[@]}"; do
    destination=$dist_dir/$(basename -- "$artifact")
    [[ ! -e $destination ]] || die "refusing to overwrite existing output: $destination"
done
for artifact in "${artifacts[@]}"; do
    destination=$dist_dir/$(basename -- "$artifact")
    cp -- "$artifact" "$destination"
    sha256sum "$destination"
done

printf 'PASS: built and extracted-package-tested %s\n' "$dist_dir/$(basename -- "$main_rpm")"
printf 'PASS: built source RPM %s\n' "$dist_dir/$(basename -- "$source_rpm")"
