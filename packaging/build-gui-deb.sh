#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

# Build the architecture-independent GUI package from tracked source. The CLI
# dependency is built and tested in baseline mode but is packaged separately.

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
output=$dist_dir/zupt-gui_${version}_all.deb
[[ ! -e $output ]] || die "refusing to overwrite existing output: $output"

for command_name in make python3 dpkg-deb gzip sha256sum; do
    command -v -- "$command_name" >/dev/null 2>&1 || \
        die "required command not found: $command_name"
done

jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-gui-deb.XXXXXXXX")
stage=$work/stage
extract=$work/extract
cleanup() {
    make -C "$repo_root" clean >/dev/null 2>&1 || true
    chmod -R u+rwX "$work" 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

printf '[GUI deb] validating source-only CLI dependency %s\n' "$version"
make clean
make -j"$jobs" V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0
make V=1 WITH_SDK=0 WITH_PQBOX=0 INSTALL_LEGACY_ALIAS=0 check
./zupt version | grep -Fq "zupt $version" || die 'CLI version check failed'

PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
from pathlib import Path
source = Path("gui/src/zupt_gui.py").read_text(encoding="utf-8")
compile(source, "gui/src/zupt_gui.py", "exec")
PY

mkdir -p -- "$stage"
bash gui/install.sh --destdir "$stage" --prefix /usr
[[ ! -e $stage/usr/bin/vaptvupt-gui ]] || die 'legacy vaptvupt-gui alias must not be packaged'

install -d -- "$stage/usr/share/doc/zupt-gui" "$stage/DEBIAN"
install -m 0644 -- gui/README.md "$stage/usr/share/doc/zupt-gui/README.md"
gzip -9n -c CHANGELOG.md >"$stage/usr/share/doc/zupt-gui/changelog.gz"
install -m 0644 -- LICENSE-AGPL-3.0 "$stage/usr/share/doc/zupt-gui/copyright"
gzip -9n -- "$stage/usr/share/man/man1/zupt-gui.1"

installed_kib=$(du -sk "$stage/usr" | awk '{print $1}')
cat >"$stage/DEBIAN/control" <<EOF
Package: zupt-gui
Version: $version
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-pyqt6 | python3-pyside6.qtwidgets, zupt (= $version)
Installed-Size: $installed_kib
Maintainer: Cristian Cezar Moisés <sac@securityops.co>
Homepage: https://github.com/cristiancmoises/zupt
Description: Qt graphical interface for the ZUPT backup utility
 The GUI creates, inspects, verifies, and extracts .zupt archives through the
 separately packaged zupt command. Optional SDK and PQ-box controls are
 shown only when the installed command reports those integrations enabled.
EOF

forbidden=$(find "$stage" -type f \( \
    -name '*.o' -o -name '*.obj' -o -name '*.a' -o -name '*.so' -o \
    -name '*.so.*' -o -name '*.dll' -o -name '*.dylib' -o -name '*.exe' \
    \) -print)
[[ -z $forbidden ]] || { printf '%s\n' "$forbidden" >&2; die 'compiled artifact in GUI package'; }

package_tmp=$work/$(basename -- "$output")
source_epoch=${SOURCE_DATE_EPOCH:-$(sed -n '1p' .source-date-epoch 2>/dev/null || true)}
[[ $source_epoch =~ ^[0-9]+$ ]] || die 'SOURCE_DATE_EPOCH is not available'
SOURCE_DATE_EPOCH=$source_epoch dpkg-deb -Zxz --build --root-owner-group \
    "$stage" "$package_tmp" >/dev/null
dpkg-deb --info "$package_tmp" >/dev/null
dpkg-deb --contents "$package_tmp" >"$work/contents.txt"
grep -q './usr/bin/zupt-gui' "$work/contents.txt" || die 'GUI launcher missing from .deb'
if grep -Eq '(/usr/bin/vaptvupt-gui|\.(o|obj|a|so|so\.[^/]+|dll|dylib|exe)$)' "$work/contents.txt"; then
    cat "$work/contents.txt" >&2
    die 'forbidden compatibility alias or compiled artifact in .deb'
fi

mkdir -p -- "$extract"
dpkg-deb --extract "$package_tmp" "$extract"
PYTHONDONTWRITEBYTECODE=1 python3 - <<PY
from pathlib import Path
p = Path("$extract/usr/lib/zupt-gui/zupt_gui.py")
compile(p.read_text(encoding="utf-8"), str(p), "exec")
PY

mv -- "$package_tmp" "$output"
sha256sum "$output"
printf 'PASS: built and content-validated %s\n' "$output"
