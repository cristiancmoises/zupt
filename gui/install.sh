#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

# Install the integrated ZUPT GUI from the checked-out source tree.
# This script never downloads Python modules or operating-system packages.

set -Eeuo pipefail

die() {
    printf 'zupt-gui install: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: gui/install.sh [OPTIONS]

  --user                 install below $HOME/.local
  --prefix DIR           installation prefix (default: /usr/local)
  --destdir DIR          staging root for package builds
  --legacy-alias         install opt-in vaptvupt-gui compatibility symlink
  -h, --help             show this help

Python 3.9+ and either PySide6 or PyQt6 must already be installed. The
zupt CLI must also be installed or selected with ZUPT_BIN at runtime.
VAPTVUPT_BIN remains a renamed-era compatibility fallback.
EOF
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
prefix=/usr/local
destdir=${DESTDIR:-}
legacy_alias=0

while (($#)); do
    case $1 in
        --user)
            [[ -n ${HOME:-} ]] || die 'HOME is unset; cannot use --user'
            prefix=$HOME/.local
            ;;
        --prefix)
            (($# >= 2)) || die '--prefix requires a directory'
            prefix=$2
            shift
            ;;
        --destdir)
            (($# >= 2)) || die '--destdir requires a directory'
            destdir=$2
            shift
            ;;
        --legacy-alias) legacy_alias=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

[[ $prefix == /* ]] || die '--prefix must be an absolute path'
[[ -z $destdir || $destdir == /* ]] || die '--destdir must be an absolute path'

bindir=${BINDIR:-$prefix/bin}
libexecdir=${LIBEXECDIR:-$prefix/lib/zupt-gui}
datadir=${DATADIR:-$prefix/share}

for source_file in \
    "$script_dir/src/zupt_gui.py" \
    "$script_dir/assets/zupt-icon.png" \
    "$script_dir/packaging/zupt-gui.desktop" \
    "$repo_root/doc/zupt-gui.1" \
    "$repo_root/LICENSE" \
    "$repo_root/LICENSE-AGPL-3.0" \
    "$script_dir/LICENSE-GUI" \
    "$script_dir/assets/README.md"; do
    [[ -f $source_file ]] || die "required source file is missing: $source_file"
done

stage_bindir=$destdir$bindir
stage_libexecdir=$destdir$libexecdir
stage_datadir=$destdir$datadir
install -d -- "$stage_bindir" "$stage_libexecdir" \
    "$stage_datadir/applications" \
    "$stage_datadir/icons/hicolor/256x256/apps" \
    "$stage_datadir/man/man1" \
    "$stage_datadir/licenses/zupt-gui"

install -m 0644 -- "$script_dir/src/zupt_gui.py" "$stage_libexecdir/zupt_gui.py"
install -m 0644 -- "$script_dir/packaging/zupt-gui.desktop" \
    "$stage_datadir/applications/zupt-gui.desktop"
install -m 0644 -- "$script_dir/assets/zupt-icon.png" \
    "$stage_datadir/icons/hicolor/256x256/apps/zupt-gui.png"
install -m 0644 -- "$repo_root/doc/zupt-gui.1" \
    "$stage_datadir/man/man1/zupt-gui.1"
install -m 0644 -- "$repo_root/LICENSE" \
    "$stage_datadir/licenses/zupt-gui/LICENSE"
install -m 0644 -- "$repo_root/LICENSE-AGPL-3.0" \
    "$stage_datadir/licenses/zupt-gui/LICENSE-AGPL-3.0"
install -m 0644 -- "$script_dir/LICENSE-GUI" \
    "$stage_datadir/licenses/zupt-gui/LICENSE-GUI"
install -m 0644 -- "$script_dir/assets/README.md" \
    "$stage_datadir/licenses/zupt-gui/ASSET-PROVENANCE.md"

# Quote the installed module path for a POSIX shell without embedding DESTDIR.
quoted_libexec=${libexecdir//\'/\'\\\'\'}
launcher_tmp=$(mktemp "${TMPDIR:-/tmp}/zupt-gui-launcher.XXXXXXXX")
trap 'rm -f -- "$launcher_tmp"' EXIT HUP INT TERM
cat >"$launcher_tmp" <<EOF
#!/bin/sh
exec python3 '$quoted_libexec/zupt_gui.py' "\$@"
EOF
install -m 0755 -- "$launcher_tmp" "$stage_bindir/zupt-gui"

if ((legacy_alias)); then
    ln -s -- zupt-gui "$stage_bindir/vaptvupt-gui"
fi

if [[ -z $destdir ]]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$datadir/applications" >/dev/null 2>&1 || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q "$datadir/icons/hicolor" >/dev/null 2>&1 || true
    fi
fi

printf 'Installed zupt-gui below %s%s\n' "$destdir" "$prefix"
if ((!legacy_alias)); then
    printf 'Legacy vaptvupt-gui alias was not installed (use --legacy-alias to opt in).\n'
fi
