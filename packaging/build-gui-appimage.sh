#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

# Build a dependency-light GUI AppImage. The ZUPT CLI is compiled from this
# tree and bundled; Python 3 plus PySide6 or PyQt6 remain host requirements.

set -Eeuo pipefail
umask 022
export LC_ALL=C

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[[ $(uname -s) == Linux ]] || die 'AppImage packages must be built on Linux'
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"
header_version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' include/zupt.h)
version=${VERSION:-$header_version}
[[ $version == "$header_version" && $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
    die "VERSION '$version' does not match include/zupt.h '$header_version'"

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

dist_dir=${DIST_DIR:-${TMPDIR:-/tmp}/zupt-release}
mkdir -p -- "$dist_dir"
dist_dir=$(cd -- "$dist_dir" && pwd -P)
case $dist_dir/ in "$repo_root"/*) die 'DIST_DIR must be outside the repository' ;; esac
output=$dist_dir/ZUPT-GUI-$version-linux-$arch.AppImage
[[ ! -e $output ]] || die "refusing to overwrite existing output: $output"

appimagetool=${APPIMAGETOOL:-appimagetool}
appimagetool=$(command -v -- "$appimagetool" 2>/dev/null || true)
[[ -n $appimagetool ]] || die 'appimagetool not found; no network fallback is performed'
runtime_file=${APPIMAGE_RUNTIME_FILE:-}
[[ -n $runtime_file && -s $runtime_file ]] || \
    die 'set APPIMAGE_RUNTIME_FILE to a non-empty verified local type-2 runtime'
runtime_file=$(cd -- "$(dirname -- "$runtime_file")" && pwd -P)/$(basename -- "$runtime_file")
runtime_compliance_file=${APPIMAGE_RUNTIME_COMPLIANCE_FILE:-}
[[ -n $runtime_compliance_file && -s $runtime_compliance_file ]] || \
    die 'set APPIMAGE_RUNTIME_COMPLIANCE_FILE to the audited runtime license/source-compliance notice'
runtime_compliance_file=$(cd -- "$(dirname -- "$runtime_compliance_file")" && pwd -P)/$(basename -- "$runtime_compliance_file")

for command_name in make python3 readelf file sha256sum; do
    command -v -- "$command_name" >/dev/null 2>&1 || \
        die "required command not found: $command_name"
done
python3 -c 'import PySide6.QtWidgets' 2>/dev/null || \
python3 -c 'import PyQt6.QtWidgets' 2>/dev/null || \
    die 'the build/test host needs PySide6 or PyQt6; the AppImage does not download it'

jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-gui-appimage.XXXXXXXX")
appdir=$work/ZUPT-GUI.AppDir
image_tmp=$work/$(basename -- "$output")
cleanup() {
    make -C "$repo_root" clean >/dev/null 2>&1 || true
    chmod -R u+rwX "$work" 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

make clean
make -j"$jobs" V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0
make V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 check
make DESTDIR="$appdir" PREFIX=/usr WITH_SDK=0 WITH_PQBOX=0 \
    INSTALL_LEGACY_ALIAS=0 install

binary=$appdir/usr/bin/zupt
[[ -x $binary ]] || die 'source-built CLI is missing from AppDir'
[[ ! -e $appdir/usr/bin/vaptvupt ]] || die 'legacy vaptvupt alias must not be packaged'
if readelf -d "$binary" 2>/dev/null | grep -Eq '(RPATH|RUNPATH|libvuptsdk|libpqvaptvupt|vendor/)'; then
    readelf -d "$binary" >&2
    die 'CLI has RPATH/RUNPATH or an optional-library reference'
fi

install -Dm0644 gui/src/zupt_gui.py "$appdir/usr/lib/zupt-gui/zupt_gui.py"
install -Dm0644 gui/assets/zupt-icon.png \
    "$appdir/usr/share/icons/hicolor/256x256/apps/zupt-gui.png"
install -Dm0644 gui/packaging/zupt-gui.desktop \
    "$appdir/usr/share/applications/zupt-gui.desktop"
install -d "$appdir/usr/share/licenses/zupt"
install -m 0644 LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 \
    LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0 NOTICE \
    THIRD-PARTY-NOTICES.md "$appdir/usr/share/licenses/zupt/"
install -d "$appdir/usr/share/licenses/zupt-gui"
install -m 0644 LICENSE-AGPL-3.0 \
    "$appdir/usr/share/licenses/zupt-gui/LICENSE-AGPL-3.0"
install -m 0644 gui/LICENSE-GUI \
    "$appdir/usr/share/licenses/zupt-gui/LICENSE-GUI"
install -m 0644 gui/assets/README.md \
    "$appdir/usr/share/licenses/zupt-gui/ASSET-PROVENANCE.md"
install -Dm0644 "$runtime_compliance_file" \
    "$appdir/usr/share/licenses/zupt/AppImage-runtime-compliance.txt"
cp -- "$appdir/usr/share/icons/hicolor/256x256/apps/zupt-gui.png" \
    "$appdir/zupt-gui.png"

cat >"$appdir/usr/bin/zupt-gui" <<'WRAP'
#!/bin/sh
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
export ZUPT_BIN=$here/bin/zupt
exec python3 "$here/lib/zupt-gui/zupt_gui.py" "$@"
WRAP
chmod 0755 "$appdir/usr/bin/zupt-gui"
cat >"$appdir/AppRun" <<'APPRUN'
#!/bin/sh
appdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec "$appdir/usr/bin/zupt-gui" "$@"
APPRUN
chmod 0755 "$appdir/AppRun"
cp -- "$appdir/usr/share/applications/zupt-gui.desktop" "$appdir/"

forbidden=$(find "$appdir" -type f \( \
    -name '*.o' -o -name '*.obj' -o -name '*.a' -o -name '*.so' -o \
    -name '*.so.*' -o -name '*.dll' -o -name '*.dylib' \
    \) -print)
[[ -z $forbidden ]] || { printf '%s\n' "$forbidden" >&2; die 'compiled library/object in AppDir'; }

QT_QPA_PLATFORM=offscreen "$appdir/AppRun" --version | grep -Fq "zupt-gui $version" || \
    die 'AppDir GUI/CLI integration check failed'
export ARCH=$arch APPIMAGE_EXTRACT_AND_RUN=1
"$appimagetool" --runtime-file "$runtime_file" "$appdir" "$image_tmp"
chmod 0755 "$image_tmp"
file "$image_tmp" | grep -q ELF || die 'generated AppImage does not have ELF magic'
QT_QPA_PLATFORM=offscreen "$image_tmp" --version | grep -Fq "zupt-gui $version" || \
    die 'generated AppImage execution check failed'

mv -- "$image_tmp" "$output"
sha256sum "$output"
printf 'PASS: built and execution-tested %s\n' "$output"
