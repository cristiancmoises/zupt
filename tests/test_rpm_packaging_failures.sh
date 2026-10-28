#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Actual RPM helpers with external tool doubles, not native qualification.
set -Eeuo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=$(sed -n 's/^#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' "$root/include/zupt.h")
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-rpm-boundaries.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
evidence=${ZUPT_TEST_EVIDENCE_DIR:-$work/logs}
mkdir -p -- "$evidence" "$work/source" "$work/bin"
source=$work/source
for name in include/zupt.h packaging/build-rpm.sh packaging/build-gui-rpm.sh \
    packaging/opensuse/zupt.spec scripts/check-installed-docs.py scripts/publish-package.py \
    gui/src/zupt_gui.py gui/assets/zupt-icon.png gui/packaging/zupt-gui.desktop \
    doc/zupt-gui.1 gui/README.md README.pt-BR.md DOCUMENTACAO.pt-BR.md \
    LICENSE LICENSE-AGPL-3.0 gui/LICENSE-GUI gui/assets/README.md \
    docs/USER_GUIDE.md docs/GUIA_USUARIO.pt-BR.md SECURITY.md DISTRIBUTION.md; do
    mkdir -p -- "$source/$(dirname -- "$name")"
    cp -- "$root/$name" "$source/$name"
done
printf '1\n' > "$source/.source-date-epoch"
cat > "$work/cli" <<'STUB'
#!/usr/bin/env bash
printf 'zupt %s\n' "$RPM_TEST_VERSION"
STUB
cat > "$source/scripts/test-installed-zupt.sh" <<'STUB'
#!/usr/bin/env bash
if [[ $RPM_TEST_PHASE == publish ]]; then
    printf 'DOUBLE: installed CLI smoke\n'
    exit 0
fi
printf 'RPM-CHECKPOINT: ELF accepted\n' >&2
exit 91
STUB
cat > "$work/bin/tool" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$RPM_TEST_TRACE"
fault() {
    printf 'RPM-FAULT: %s exit=%s\n' "$RPM_TEST_MODE" "$1" | tee -a "$RPM_TEST_TRACE" >&2
    exit "$1"
}
checkpoint() { printf 'RPM-CHECKPOINT: metadata accepted\n' >&2; exit 91; }
case $name in
    make)
        archive=
        for arg in "$@"; do
            case $arg in DIST_TARBALL=*) archive=${arg#DIST_TARBALL=} ;; esac
        done
        if [[ -n $archive ]]; then
            tree=$RPM_TEST_CASE/zupt-$RPM_TEST_VERSION
            mkdir -p -- "$tree/include"
            cp -- include/zupt.h "$tree/include/"
            tar -czf "$archive" -C "$RPM_TEST_CASE" "zupt-$RPM_TEST_VERSION"
        elif [[ $* != *clean* ]]; then
            install -m0755 "$RPM_TEST_CLI" ./zupt
        fi ;;
    rpmbuild)
        top=${2#_topdir }
        mkdir -p -- "$top/RPMS/noarch" "$top/SRPMS"
        printf 'DOUBLE RPM\n' > "$top/RPMS/noarch/$RPM_TEST_PACKAGE-$RPM_TEST_VERSION-$RPM_TEST_RELEASE.noarch.rpm"
        printf 'DOUBLE SRPM\n' > "$top/SRPMS/$RPM_TEST_PACKAGE-$RPM_TEST_VERSION-$RPM_TEST_RELEASE.src.rpm" ;;
    find)
        role=main
        [[ $1 != */SRPMS ]] || role=source
        [[ $RPM_TEST_MODE != empty-$role ]] || exit 0
        "$RPM_TEST_FIND" "$@"
        [[ $RPM_TEST_MODE != find-$role ]] || fault 75 ;;
    sort)
        # Each producer writes its identity in the input: paths vs member names.
        input=$(cat)
        role=members
        [[ $input != */RPMS/* ]] || role=main
        [[ $input != */SRPMS/* ]] || role=source
        if [[ -n $input ]]; then printf '%s\n' "$input"; fi | "$RPM_TEST_SORT" "$@"
        [[ $RPM_TEST_MODE != sort-$role ]] || fault 77 ;;
    rpm)
        package=${@: -1}
        role=main
        [[ $package != *.src.rpm ]] || role=source
        case $1 in
            -qp)
                field=$3
                case $field in
                    '%{NAME}') value=$RPM_TEST_PACKAGE ;;
                    '%{VERSION}') value=$RPM_TEST_VERSION ;;
                    '%{RELEASE}') value=$RPM_TEST_RELEASE ;;
                    '%{SOURCEPACKAGE}')
                        value='(none)'; [[ $role != source ]] || value=1 ;;
                    '%{SOURCERPM}')
                        value='(none)'
                        [[ $role != main ]] || value=$RPM_TEST_PACKAGE-$RPM_TEST_VERSION-$RPM_TEST_RELEASE.src.rpm ;;
                    *) exit 92 ;;
                esac
                printf '%s' "$value"
                field=${field#'%{'}; field=${field%'}'}
                [[ $RPM_TEST_MODE != metadata-$role-$field ]] || fault 73 ;;
            -qpl)
                if [[ $role == source ]]; then
                    printf '%s\n' "$RPM_TEST_PACKAGE-$RPM_TEST_VERSION.tar.gz" "$RPM_TEST_PACKAGE.spec"
                    [[ $RPM_TEST_MODE != source-list ]] || fault 74
                else
                    [[ $RPM_TEST_PHASE != metadata ]] || checkpoint
                    printf '/usr/bin/%s\n' "$RPM_TEST_PACKAGE"
                fi ;;
            -qpi) [[ $RPM_TEST_PHASE != metadata ]] || checkpoint ;;
            *) exit 93 ;;
        esac ;;
    rpm2cpio) printf 'DOUBLE CPIO\n' ;;
    cpio)
        cat >/dev/null
        if [[ $RPM_TEST_PACKAGE == zupt-gui ]]; then
            install -Dm0644 "$RPM_TEST_SOURCE/gui/src/zupt_gui.py" usr/share/zupt-gui/zupt_gui.py
        else
            install -Dm0755 "$RPM_TEST_CLI" usr/bin/zupt
        fi
        doc=usr/share/doc/$RPM_TEST_PACKAGE
        mkdir -p "$doc/docs"
        install -m0644 -- "$RPM_TEST_SOURCE/SECURITY.md" "$RPM_TEST_SOURCE/DISTRIBUTION.md" "$doc/"
        install -m0644 -- "$RPM_TEST_SOURCE/docs/USER_GUIDE.md" "$RPM_TEST_SOURCE/docs/GUIA_USUARIO.pt-BR.md" "$doc/docs/" ;;
    readelf)
        case $1 in
            -h) role=header; output='  Type: DYN (Position-Independent Executable file)' ;;
            -W) role=program; output=$' GNU_RELRO 0x0\n GNU_STACK 0x0 RW 0x10' ;;
            -d)
                role=dynamic; output=' (NEEDED) Shared library: [libc.so.6]'
                case $RPM_TEST_MODE in
                    rpath) output=' (RUNPATH) Library runpath: [/unsafe]' ;;
                    vendor) output=' (NEEDED) Shared library: [libpqvaptvupt.so]' ;;
                esac ;;
            *) exit 94 ;;
        esac
        [[ $RPM_TEST_MODE != readelf-$role-empty ]] || fault 76
        printf '%s\n' "$output"
        [[ $RPM_TEST_MODE != readelf-$role-safe ]] || fault 76 ;;
    *) exit 95 ;;
esac
STUB
chmod 0755 "$work/bin/tool" "$work/cli"
real_find=$(command -v find)
real_sort=$(command -v sort)
for name in make rpmbuild find sort rpm rpm2cpio cpio readelf; do
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
    helper=$1 mode=$2 phase=$3 expected=$4
    case_dir=$work/$helper-$mode-$phase
    mkdir -p -- "$case_dir/dist" "$case_dir/tmp"
    : > "$case_dir/trace"
    package=zupt release=0 script=$source/packaging/build-rpm.sh
    if [[ $helper == gui ]]; then
        package=zupt-gui release=1 script=$source/packaging/build-gui-rpm.sh
    fi
    main_output=$case_dir/dist/$package-$version-$release.noarch.rpm
    source_output=$case_dir/dist/$package-$version-$release.src.rpm
    case $mode in
        existing-source) printf 'foreign source bytes\n' > "$source_output" ;;
        dangling-source) ln -s "$case_dir/missing" "$source_output" ;;
        dangling-main) ln -s "$case_dir/missing" "$main_output" ;;
    esac
    if PATH="$work/bin:$PATH" DIST_DIR="$case_dir/dist" TMPDIR="$case_dir/tmp" \
        JOBS=2 SOURCE_DATE_EPOCH=1 RPM_TEST_MODE="$mode" RPM_TEST_PHASE="$phase" \
        RPM_TEST_PACKAGE="$package" RPM_TEST_RELEASE="$release" RPM_TEST_VERSION="$version" \
        RPM_TEST_TRACE="$case_dir/trace" RPM_TEST_SOURCE="$source" RPM_TEST_CASE="$case_dir" \
        RPM_TEST_CLI="$work/cli" RPM_TEST_FIND="$real_find" RPM_TEST_SORT="$real_sort" \
        timeout 15 bash "$script" > "$evidence/$helper-$mode-$phase.log" 2>&1; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" > "$evidence/$helper-$mode-$phase.exit"
    cp -- "$case_dir/trace" "$evidence/$helper-$mode-$phase.trace"
    if [[ $phase == publish ]]; then
        check test "$status" -eq "$expected"
        if ((expected == 0)); then
            check grep -Fq 'PASS: built and ' "$evidence/$helper-$mode-$phase.log"
            check test "$(<"$main_output")" = 'DOUBLE RPM'
            check test "$(<"$source_output")" = 'DOUBLE SRPM'
        else
            check test "$(grep -Fc 'PASS: built and ' "$evidence/$helper-$mode-$phase.log" || true)" -eq 0
            case $mode in
                existing-source)
                    check test "$(<"$source_output")" = 'foreign source bytes'
                    check test ! -e "$main_output" ;;
                dangling-source)
                    check test -L "$source_output"
                    check test ! -e "$main_output" ;;
                dangling-main)
                    check test -L "$main_output"
                    check test ! -e "$source_output" ;;
            esac
            check test ! -e "$case_dir/missing"
        fi
        check test -z "$(find "$case_dir/dist" -mindepth 1 -name '.zupt-publish-*' -print)"
        check test -z "$(find "$case_dir/tmp" -mindepth 1 -print)"
        exit 0
    elif ((expected == 91)); then
        marker='RPM-CHECKPOINT: metadata accepted'
        [[ $phase != elf ]] || marker='RPM-CHECKPOINT: ELF accepted'
        check grep -Fq "$marker" "$evidence/$helper-$mode-$phase.log"
    elif [[ $mode != empty-* && $mode != rpath && $mode != vendor ]]; then
        check grep -Fq "RPM-FAULT: $mode exit=$expected" "$evidence/$helper-$mode-$phase.trace"
        check grep -Fq "RPM-FAULT: $mode exit=$expected" "$evidence/$helper-$mode-$phase.log"
    elif [[ $mode == empty-* ]]; then
        check grep -Fq 'found 0' "$evidence/$helper-$mode-$phase.log"
    else
        marker='RPM executable contains RPATH/RUNPATH'
        [[ $mode != vendor ]] || marker='RPM executable references a vendored optional library'
        check grep -Fq "$marker" "$evidence/$helper-$mode-$phase.log"
    fi
    if ((expected != 91)); then
        check test "$(grep -c 'RPM-CHECKPOINT:' "$evidence/$helper-$mode-$phase.log" || true)" -eq 0
    fi
    check test "$status" -eq "$expected"
    check test -z "$(find "$case_dir/dist" -mindepth 1 -print)"
    check test -z "$(find "$case_dir/tmp" -mindepth 1 -print)"
)
case_test() {
    local status
    set +e
    run_case "$@"
    status=$?
    set -e
    if ((status == 0)); then
        passed=$((passed + 1)); printf 'PASS: %s %s %s (exit %s)\n' "$@"
    else
        failed=$((failed + 1)); printf 'FAIL: %s %s %s (expected %s)\n' "$@" >&2
    fi
}
for helper in cli gui; do
    case_test "$helper" normal metadata 91
    for role in main source; do
        for field in NAME VERSION RELEASE SOURCEPACKAGE SOURCERPM; do
            case_test "$helper" "metadata-$role-$field" metadata 73
        done
        case_test "$helper" "find-$role" metadata 75
        case_test "$helper" "sort-$role" metadata 77
        case_test "$helper" "empty-$role" metadata 1
    done
    case_test "$helper" source-list metadata 74
    case_test "$helper" sort-members metadata 77
done
case_test cli normal elf 91
for section in header program dynamic; do
    for output in empty safe; do
        case_test cli "readelf-$section-$output" elf 76
    done
done
case_test cli rpath elf 1
case_test cli vendor elf 1
for helper in cli gui; do
    case_test "$helper" normal publish 0
    for mode in existing-source dangling-source dangling-main; do
        case_test "$helper" "$mode" publish 1
    done
done
printf 'SUMMARY: PASS=%d FAIL=%d (tool doubles; no native qualification)\n' "$passed" "$failed"
((failed == 0))
