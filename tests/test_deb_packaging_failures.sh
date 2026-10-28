#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Full DEB helpers with build/package-tool doubles; not native qualification.
set -Eeuo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' "$root/include/zupt.h")
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-deb-boundaries.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
evidence=${ZUPT_TEST_EVIDENCE_DIR:-$work/logs}
mkdir -p -- "$evidence" "$work/source" "$work/bin"
source=$work/source
# Copy only the actual helpers and their source/documentation inputs.
for name in include/zupt.h packaging/build-deb.sh packaging/build-gui-deb.sh \
    gui/install.sh gui/src/zupt_gui.py gui/assets/zupt-icon.png \
    gui/packaging/zupt-gui.desktop doc/zupt-gui.1 gui/README.md \
    gui/LICENSE-GUI gui/assets/README.md scripts/check-installed-docs.py \
    scripts/publish-package.py \
    README.md README.pt-BR.md DOCUMENTACAO.pt-BR.md CHANGELOG.md SECURITY.md \
    DISTRIBUTION.md THREAT_MODEL.md NOTICE THIRD-PARTY-NOTICES.md LICENSE \
    LICENSE-AGPL-3.0 LICENSE-GPL-3.0 LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause \
    LICENSE-CC0-1.0 docs/USER_GUIDE.md docs/GUIA_USUARIO.pt-BR.md; do
    mkdir -p -- "$source/$(dirname -- "$name")"
    cp -- "$root/$name" "$source/$name"
done
printf '1\n' > "$source/.source-date-epoch"
cat > "$work/cli" <<'STUB'
#!/usr/bin/env bash
printf 'zupt %s\n' "$DEB_TEST_VERSION"
STUB
cat > "$source/scripts/test-installed-zupt.sh" <<'STUB'
#!/usr/bin/env bash
set -eu
[[ -x $1 ]]
printf 'DOUBLE: installed CLI smoke\n'
STUB
cat > "$work/bin/tool" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$DEB_TEST_TRACE"
case $name in
    dpkg) [[ $* == --print-architecture ]]; printf 'testarch\n' ;;
    make)
        for arg in "$@"; do
            case $arg in DESTDIR=*) stage=${arg#DESTDIR=} ;; esac
        done
        if [[ ${*: -1} == install ]]; then
            install -Dm0755 "$DEB_TEST_CLI" "$stage/usr/bin/zupt"
        elif [[ $* != *clean* ]]; then
            install -m0755 "$DEB_TEST_CLI" ./zupt
        fi ;;
    readelf)
        if [[ $DEB_TEST_MODE == readelf-* ]]; then
            printf 'DEB-FAULT: readelf-dynamic exit=73 mode=%s\n' "$DEB_TEST_MODE" >> "$DEB_TEST_TRACE"
            [[ $DEB_TEST_MODE != readelf-safe ]] || \
                printf 'Dynamic section at offset 0 contains 0 entries:\n'
            printf 'DEB-FAULT: readelf-dynamic exit=73 mode=%s\n' "$DEB_TEST_MODE" >&2
            exit 73
        fi
        case $DEB_TEST_MODE in
            rpath) printf ' (RUNPATH) Library runpath: [/unsafe]\n' ;;
            vendor) printf ' (NEEDED) Shared library: [libpqvaptvupt.so]\n' ;;
            *) printf 'Dynamic section at offset 0 contains 0 entries:\n' ;;
        esac ;;
    dpkg-deb)
        case $* in
            *--build*)
                stage=${@: -2:1}
                package=${@: -1}
                cp -a -- "$stage" "$DEB_TEST_STAGE"
                printf 'DOUBLE DEB PAYLOAD\n' > "$package" ;;
            --info*) ;;
            --contents*) printf './usr/bin/zupt\n./usr/bin/zupt-gui\n' ;;
            --extract*)
                cp -a -- "$DEB_TEST_STAGE/." "$3/"
                case $DEB_TEST_MODE in
                    late-regular) printf 'foreign package bytes\n' > "$DEB_TEST_OUTPUT" ;;
                    late-symlink) ln -s "$DEB_TEST_TARGET" "$DEB_TEST_OUTPUT" ;;
                    late-dangling) ln -s "$DEB_TEST_TARGET.missing" "$DEB_TEST_OUTPUT" ;;
                    late-directory)
                        mkdir -- "$DEB_TEST_OUTPUT"
                        printf 'foreign child\n' > "$DEB_TEST_OUTPUT/sentinel" ;;
                esac ;;
            *) exit 91 ;;
        esac ;;
    *) exit 92 ;;
esac
STUB
chmod 0755 "$work/bin/tool" "$work/cli"
for name in make dpkg dpkg-deb readelf; do
    ln -s tool "$work/bin/$name"
done
passed=0
failed=0
check() {
    if "$@"; then return 0; fi
    printf 'ASSERTION FAILED: %s\n' "$*" >&2
    exit 1
}
run_case() (
    set -Eeuo pipefail
    local helper=$1 mode=$2 kind=$3 case_dir output target status script
    case_dir=$work/$helper-$mode-$kind
    mkdir -p -- "$case_dir/dist" "$case_dir/tmp"
    output=$case_dir/dist/zupt_${version}_testarch.deb
    [[ $helper != gui ]] || output=$case_dir/dist/zupt-gui_${version}_all.deb
    script=$source/packaging/build-deb.sh
    [[ $helper != gui ]] || script=$source/packaging/build-gui-deb.sh
    : > "$case_dir/trace"
    target=$case_dir/sentinel
    printf 'preserve target bytes\n' > "$target"
    cp -- "$target" "$case_dir/sentinel.expected"
    case $kind in
        dangling) ln -s "$case_dir/missing" "$output" ;;
        symlink) ln -s "$target" "$output" ;;
        regular) cp -- "$target" "$output" ;;
    esac
    if PATH="$work/bin:$PATH" DIST_DIR="$case_dir/dist" TMPDIR="$case_dir/tmp" \
        RUN_CHECKS=0 JOBS=2 SOURCE_DATE_EPOCH=1 DEB_DEPENDS=libc6 \
        DEB_TEST_MODE="$mode" DEB_TEST_TRACE="$case_dir/trace" \
        DEB_TEST_OUTPUT="$output" DEB_TEST_TARGET="$target" \
        DEB_TEST_VERSION="$version" \
        DEB_TEST_CLI="$work/cli" DEB_TEST_STAGE="$case_dir/staged" \
        timeout 15 bash "$script" \
        > "$evidence/$helper-$mode-$kind.log" 2>&1; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" > "$evidence/$helper-$mode-$kind.exit"
    cp -- "$case_dir/trace" "$evidence/$helper-$mode-$kind.trace"
    check test "$status" -ne 124
    check cmp -- "$target" "$case_dir/sentinel.expected"
    if [[ $kind != absent ]]; then
        check test "$status" -ne 0
        check grep -Fq 'refusing to overwrite existing output:' "$evidence/$helper-$mode-$kind.log"
        case $kind in
            dangling)
                check test -L "$output"
                check test "$(readlink -- "$output")" = "$case_dir/missing"
                check test ! -e "$case_dir/missing" ;;
            symlink)
                check test -L "$output"
                check test "$(readlink -- "$output")" = "$target" ;;
            regular) check cmp -- "$output" "$case_dir/sentinel.expected" ;;
        esac
    elif [[ $mode == late-* ]]; then
        check test "$status" -ne 0
        check test "$(grep -Fc 'PASS: built and ' "$evidence/$helper-$mode-$kind.log" || true)" -eq 0
        case $mode in
            late-regular) check test "$(<"$output")" = 'foreign package bytes' ;;
            late-symlink)
                check test -L "$output"
                check test "$(readlink -- "$output")" = "$target" ;;
            late-dangling)
                check test -L "$output"
                check test "$(readlink -- "$output")" = "$target.missing"
                check test ! -e "$target.missing" ;;
            late-directory)
                check test -d "$output"
                check test "$(find "$output" -mindepth 1 -maxdepth 1 -printf '%f\n')" = sentinel
                check test "$(<"$output/sentinel")" = 'foreign child' ;;
        esac
    elif [[ $mode == readelf-* ]]; then
        check grep -Fq "DEB-FAULT: readelf-dynamic exit=73 mode=$mode" \
            "$evidence/$helper-$mode-$kind.trace"
        check grep -Fq "DEB-FAULT: readelf-dynamic exit=73 mode=$mode" \
            "$evidence/$helper-$mode-$kind.log"
        check grep -Fq 'readelf -d ' "$evidence/$helper-$mode-$kind.trace"
        check test "$status" -eq 73
        check test ! -e "$output"
        check test ! -L "$output"
        check test -z "$(find "$case_dir/dist" -mindepth 1 -print)"
    elif [[ $mode == rpath || $mode == vendor ]]; then
        check test "$status" -eq 1
        marker='staged executable contains RPATH/RUNPATH'
        [[ $mode != vendor ]] || marker='staged executable references a vendored optional library'
        check grep -Fq "$marker" "$evidence/$helper-$mode-$kind.log"
        check grep -Fq 'readelf -d ' "$evidence/$helper-$mode-$kind.trace"
        check test "$(grep -Fc 'dpkg-deb --build' "$evidence/$helper-$mode-$kind.trace" || true)" -eq 0
        check test -z "$(find "$case_dir/dist" -mindepth 1 -print)"
    else
        check test "$status" -eq 0
        check grep -Fq 'PASS: built and ' "$evidence/$helper-$mode-$kind.log"
        check grep -Fxq 'DOUBLE DEB PAYLOAD' "$output"
        check grep -Fq 'dpkg-deb --extract ' "$evidence/$helper-$mode-$kind.trace"
    fi
    check test -z "$(find "$case_dir/tmp" -mindepth 1 -print)"
)
case_test() {
    local status
    set +e
    run_case "$@"
    status=$?
    set -e
    if ((status == 0)); then
        passed=$((passed + 1)); printf 'PASS: %s %s %s\n' "$@"
    else
        failed=$((failed + 1)); printf 'FAIL: %s %s %s\n' "$@" >&2
    fi
}
for helper in cli gui; do
    case_test "$helper" normal absent
    for kind in regular symlink dangling; do
        case_test "$helper" normal "$kind"
    done
    for mode in late-regular late-symlink late-dangling late-directory; do
        case_test "$helper" "$mode" absent
    done
done
case_test cli readelf-empty absent
case_test cli readelf-safe absent
case_test cli rpath absent
case_test cli vendor absent
printf 'SUMMARY: PASS=%d FAIL=%d (tool doubles; no native qualification)\n' "$passed" "$failed"
((failed == 0))
