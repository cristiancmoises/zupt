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

[[ $(uname -s) == Linux ]] || die 'AppImage packages must be built on Linux'

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

header_version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' include/zupt.h)
version=${VERSION:-$header_version}
[[ -n $version && $version == "$header_version" ]] || \
    die "VERSION '$version' does not match include/zupt.h '$header_version'"
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid package version: $version"

case $(uname -m) in
    x86_64|amd64) native_arch=x86_64 ;;
    aarch64|arm64) native_arch=aarch64 ;;
    *) die "unsupported native AppImage architecture: $(uname -m)" ;;
esac
case ${ARCH:-$native_arch} in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) die "unsupported AppImage architecture: ${ARCH:-$native_arch}" ;;
esac
[[ $arch == "$native_arch" ]] || \
    die "ARCH=$arch does not match the native build architecture $native_arch"

appimagetool=${APPIMAGETOOL:-appimagetool}
if [[ $appimagetool == */* ]]; then
    [[ -x $appimagetool ]] || die "APPIMAGETOOL is not executable: $appimagetool"
    appimagetool=$(cd -- "$(dirname -- "$appimagetool")" && pwd -P)/$(basename -- "$appimagetool")
else
    appimagetool=$(command -v -- "$appimagetool" || true)
    [[ -n $appimagetool ]] || die 'appimagetool not found; set APPIMAGETOOL to a verified local executable'
fi
runtime_file=${APPIMAGE_RUNTIME_FILE:-}
[[ -n $runtime_file && -s $runtime_file ]] || \
    die 'set APPIMAGE_RUNTIME_FILE to a locally verified type-2 runtime (network downloads are not performed)'
runtime_file=$(cd -- "$(dirname -- "$runtime_file")" && pwd -P)/$(basename -- "$runtime_file")
runtime_compliance_file=${APPIMAGE_RUNTIME_COMPLIANCE_FILE:-}
[[ -n $runtime_compliance_file && -s $runtime_compliance_file ]] || \
    die 'set APPIMAGE_RUNTIME_COMPLIANCE_FILE to the audited runtime license/source-compliance notice'
runtime_compliance_file=$(cd -- "$(dirname -- "$runtime_compliance_file")" && pwd -P)/$(basename -- "$runtime_compliance_file")

dist_dir=${DIST_DIR:-${TMPDIR:-/tmp}/zupt-release}
mkdir -p -- "$dist_dir"
dist_dir=$(cd -- "$dist_dir" && pwd -P)
output=$dist_dir/zupt-${version}-linux-${arch}.AppImage
[[ ! -e $output ]] || die "refusing to overwrite existing output: $output"

for command_name in make readelf file sha256sum; do
    command -v -- "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done
run_checks=${RUN_CHECKS:-1}
[[ $run_checks == 0 || $run_checks == 1 ]] || die 'RUN_CHECKS must be 0 or 1'
if [[ $run_checks == 1 ]]; then
    command -v git >/dev/null 2>&1 || die 'git is required when RUN_CHECKS=1'
fi

jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-appimage.XXXXXXXX")
appdir=$work/ZUPT.AppDir
image_tmp=$work/$(basename -- "$output")

cleanup() {
    make -C "$repo_root" clean >/dev/null 2>&1 || true
    chmod -R u+rwX "$work" 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

printf '[AppImage] source-only build of ZUPT %s (%s)\n' "$version" "$arch"
make clean
make -j"$jobs" V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0
if [[ $run_checks == 1 ]]; then
    make V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 check
fi
make DESTDIR="$appdir" PREFIX=/usr WITH_SDK=0 WITH_PQBOX=0 \
    INSTALL_LEGACY_ALIAS=0 install

binary=$appdir/usr/bin/zupt
[[ -x $binary ]] || die 'AppDir executable is missing'
[[ ! -e $appdir/usr/bin/vaptvupt ]] || die 'legacy vaptvupt alias must not be packaged'
if readelf -d "$binary" 2>/dev/null | grep -Eq '(RPATH|RUNPATH)'; then
    readelf -d "$binary" | grep -E '(RPATH|RUNPATH)' >&2
    die 'AppDir executable contains RPATH/RUNPATH'
fi
if readelf -d "$binary" 2>/dev/null | grep -Eqi '(vendor/|libvuptsdk|libpqvaptvupt)'; then
    die 'AppDir executable references a vendored optional library'
fi

mkdir -p -- "$appdir/usr/share/applications" \
    "$appdir/usr/share/doc/zupt" \
    "$appdir/usr/share/icons/hicolor/128x128/apps" \
    "$appdir/usr/share/licenses/zupt"
install -m 0644 README.md CHANGELOG.md SECURITY.md THREAT_MODEL.md \
    "$appdir/usr/share/doc/zupt/"
install -m 0644 LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 \
    LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0 NOTICE \
    THIRD-PARTY-NOTICES.md "$appdir/usr/share/licenses/zupt/"
install -m 0644 gui/LICENSE-GUI \
    "$appdir/usr/share/licenses/zupt/GUI-LICENSE.txt"
install -m 0644 gui/assets/README.md \
    "$appdir/usr/share/licenses/zupt/GUI-ASSET-PROVENANCE.md"
install -m 0644 "$runtime_compliance_file" \
    "$appdir/usr/share/licenses/zupt/AppImage-runtime-compliance.txt"
install -m 0644 gui/assets/zupt-128.png \
    "$appdir/usr/share/icons/hicolor/128x128/apps/zupt.png"
cp -- "$appdir/usr/share/icons/hicolor/128x128/apps/zupt.png" "$appdir/zupt.png"
ln -s -- zupt.png "$appdir/.DirIcon"

desktop_file=dev.zupt.cli.desktop
cat > "$appdir/$desktop_file" <<'EOF'
[Desktop Entry]
Type=Application
Name=ZUPT
Comment=Backup compression with authenticated and post-quantum encryption
Exec=zupt
Icon=zupt
Terminal=true
Categories=Utility;Archiving;
EOF
cp -- "$appdir/$desktop_file" "$appdir/usr/share/applications/$desktop_file"

cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
set -eu
appdir=$(CDPATH= cd -P "$(dirname "$0")" && pwd -P)
exec "$appdir/usr/bin/zupt" "$@"
EOF
chmod 0755 "$appdir/AppRun"

forbidden=$(find "$appdir" -type f \( \
    -name '*.o' -o -name '*.obj' -o -name '*.a' -o -name '*.so' -o \
    -name '*.so.*' -o -name '*.dll' -o -name '*.dylib' \
    \) -print)
[[ -z $forbidden ]] || {
    printf '%s\n' "$forbidden" >&2
    die 'compiled library or object found in AppDir'
}

bash scripts/test-installed-zupt.sh "$appdir/AppRun"

export ARCH=$arch
export VERSION=$version
export APPIMAGE_EXTRACT_AND_RUN=1
"$appimagetool" --runtime-file "$runtime_file" "$appdir" "$image_tmp"
chmod 0755 "$image_tmp"
file "$image_tmp" | grep -q 'ELF' || die 'generated AppImage does not have ELF magic'
bash scripts/test-installed-zupt.sh "$image_tmp"

mv -- "$image_tmp" "$output"
sha256sum "$output"
printf 'PASS: built and executed-package-tested %s\n' "$output"
