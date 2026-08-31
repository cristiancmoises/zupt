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

native_arch=$(dpkg --print-architecture)
arch=${ARCH:-$native_arch}
[[ $arch == "$native_arch" ]] || \
    die "ARCH=$arch does not match the native dpkg architecture $native_arch"
dist_dir=${DIST_DIR:-${TMPDIR:-/tmp}/zupt-release}
mkdir -p -- "$dist_dir"
dist_dir=$(cd -- "$dist_dir" && pwd -P)
output=$dist_dir/zupt_${version}_${arch}.deb
[[ ! -e $output ]] || die "refusing to overwrite existing output: $output"

for command_name in make dpkg dpkg-deb readelf sha256sum; do
    command -v -- "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done
run_checks=${RUN_CHECKS:-1}
[[ $run_checks == 0 || $run_checks == 1 ]] || die 'RUN_CHECKS must be 0 or 1'
if [[ $run_checks == 1 ]]; then
    command -v git >/dev/null 2>&1 || die 'git is required when RUN_CHECKS=1'
fi

jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-deb.XXXXXXXX")
stage=$work/stage
extract=$work/extract

cleanup() {
    make -C "$repo_root" clean >/dev/null 2>&1 || true
    chmod -R u+rwX "$work" 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

printf '[deb] source-only build of ZUPT %s (%s)\n' "$version" "$arch"
make clean
make -j"$jobs" V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0
if [[ $run_checks == 1 ]]; then
    make V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 check
fi

make DESTDIR="$stage" PREFIX=/usr WITH_SDK=0 WITH_PQBOX=0 \
    INSTALL_LEGACY_ALIAS=0 install

binary=$stage/usr/bin/zupt
[[ -x $binary ]] || die 'staged /usr/bin/zupt is missing'
[[ ! -e $stage/usr/bin/vaptvupt ]] || die 'legacy /usr/bin/vaptvupt must not be packaged'

if readelf -d "$binary" 2>/dev/null | grep -Eq '(RPATH|RUNPATH)'; then
    readelf -d "$binary" | grep -E '(RPATH|RUNPATH)' >&2
    die 'staged executable contains RPATH/RUNPATH'
fi
if readelf -d "$binary" 2>/dev/null | grep -Eqi '(vendor/|libvuptsdk|libpqvaptvupt)'; then
    die 'staged executable references a vendored optional library'
fi

forbidden=$(find "$stage" -type f \( \
    -name '*.o' -o -name '*.obj' -o -name '*.a' -o -name '*.so' -o \
    -name '*.so.*' -o -name '*.dll' -o -name '*.dylib' -o -name '*.exe' \
    \) -print)
[[ -z $forbidden ]] || {
    printf '%s\n' "$forbidden" >&2
    die 'compiled library or object found in package staging tree'
}

docdir=$stage/usr/share/doc/zupt
mkdir -p -- "$docdir"
install -m 0644 README.md CHANGELOG.md SECURITY.md "$docdir/"
for document in THREAT_MODEL.md NOTICE THIRD-PARTY-NOTICES.md LICENSE-AGPL-3.0 LICENSE-GPL-3.0 LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0; do
    [[ ! -f $document ]] || install -m 0644 "$document" "$docdir/"
done
install -m 0644 LICENSE "$docdir/copyright"

mkdir -p -- "$work/debian" "$stage/DEBIAN"
if [[ -n ${DEB_DEPENDS:-} ]]; then
    depends=$DEB_DEPENDS
else
    command -v dpkg-shlibdeps >/dev/null 2>&1 || \
        die 'dpkg-shlibdeps is required unless DEB_DEPENDS is explicitly set'
    printf 'Source: zupt\nPackage: zupt\n' > "$work/debian/control"
    shlib_line=$(cd -- "$work" && dpkg-shlibdeps -O -e"$binary")
    depends=${shlib_line#shlibs:Depends=}
    [[ -n $depends && $depends != "$shlib_line" ]] || \
        die 'dpkg-shlibdeps did not determine runtime dependencies'
fi

installed_kib=$(du -sk "$stage/usr" | awk '{print $1}')
cat > "$stage/DEBIAN/control" <<EOF
Package: zupt
Version: $version
Section: utils
Priority: optional
Architecture: $arch
Depends: $depends
Installed-Size: $installed_kib
Maintainer: Cristian Cezar Moisés <sac@securityops.co>
Homepage: https://github.com/cristiancmoises/zupt
Description: Backup compression with authenticated and post-quantum encryption
 ZUPT creates compressed backup archives with optional password encryption
 or ML-KEM-768 and X25519 hybrid key encapsulation. This package is built from
 source with the optional libvuptsdk and libpqvaptvupt integrations disabled.
EOF

package_tmp=$work/$(basename -- "$output")
dpkg-deb --build --root-owner-group "$stage" "$package_tmp" >/dev/null
dpkg-deb --info "$package_tmp" >/dev/null
dpkg-deb --contents "$package_tmp" > "$work/contents.txt"
if grep -Eq '(/usr/bin/vaptvupt$|\.(o|obj|a|so|so\.[^/]+|dll|dylib)$)' "$work/contents.txt"; then
    cat "$work/contents.txt" >&2
    die 'forbidden alias or compiled library/object found in .deb contents'
fi

mkdir -p -- "$extract"
dpkg-deb --extract "$package_tmp" "$extract"
bash scripts/test-installed-zupt.sh "$extract/usr/bin/zupt"

mv -- "$package_tmp" "$output"
sha256sum "$output"
printf 'PASS: built and extracted-package-tested %s\n' "$output"
