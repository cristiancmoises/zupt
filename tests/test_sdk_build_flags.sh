#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Check actual GNU make recipes without compiling or requiring providers.
set -Eeuo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-sdk-build-flags.XXXXXXXX")
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$work"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
passed=0 failed=0
check() {
    if "$@"; then
        passed=$((passed + 1)); printf 'PASS: %s\n' "$label"
    else
        failed=$((failed + 1)); printf 'FAIL: %s\n' "$label" >&2
    fi
}
dry_run() {
    "${MAKE:-make}" --no-print-directory -B -n V=1 "CC=${CC:-cc}" \
        TARGET_MACHINE=x86_64-linux-gnu WITH_SDK=0 WITH_PQBOX=0 \
        SDK_BUILD_DIR=sdk/build \
        "CPPFLAGS=${CPPFLAGS:-} -DZUPT_TEST_CALLER_CPPFLAGS" "$@" > "$work/recipes" 2>&1 || {
        cat "$work/recipes"; return 1;
    }
    cat "$work/recipes"
}
for enabled in 0 1; do
    for unit in zupt_sha256_shani vv_ans vaptvupt_api zupt_crypto zupt_x25519 zuptsdk; do
        object=sdk/build/$unit.o
        dry_run "WITH_JASMIN=$enabled" "$object"
        command_line=$(awk -v target="$object" \
            'sub(/\\$/, "") { continued=continued $0; next }
             { line=continued $0; continued=""
               if (index(line, " -c ") && index(line, "-o " target " ")) { print line; n++ } }
             END { if (n != 1) exit 1 }' "$work/recipes")
        label="$unit WITH_JASMIN=$enabled preserves caller CPPFLAGS"
        check test "${command_line#* -DZUPT_TEST_CALLER_CPPFLAGS }" != "$command_line"
        label="$unit WITH_JASMIN=$enabled selects assembly macro"
        if [[ $enabled == 1 ]]; then
            check test "${command_line#* -DZUPT_USE_JASMIN }" != "$command_line"
        else
            check test "${command_line#* -DZUPT_USE_JASMIN }" = "$command_line"
        fi
    done
done
dry_run WITH_JASMIN=1 WITH_SDK=1 SDK_CPPFLAGS=-DZUPT_TEST_EXTERNAL_SDK \
    SDK_LDLIBS=-lzupt_test_external_sdk WITH_PQBOX=1 \
    PQBOX_CPPFLAGS=-DZUPT_TEST_EXTERNAL_PQBOX PQBOX_LDLIBS=-lzupt_test_external_pqbox \
    sdk-shared
label='external CLI provider flags and libraries stay out of SDK recipes'
provider_status=0
grep -Eq -- 'ZUPT_WITH_(SDK|PQBOX)|ZUPT_TEST_EXTERNAL_(SDK|PQBOX)|-lzupt_test_external_(sdk|pqbox)' \
    "$work/recipes" || provider_status=$?
check test "$provider_status" -eq 1

# Execute the real symbol target. A producer that fails after emitting valid
# output must fail the target, even when later pipeline stages succeed.
# Keep these tools separate from the parent PATH used by the existing checks.
symbol_bin="$work/symbol-bin"
mkdir -p "$symbol_bin"
make_bin=$(command -v "${MAKE:-make}")
real_awk=$(command -v awk)
real_sed=$(command -v sed)
real_sort=$(command -v sort)
real_grep=$(command -v grep)
real_tr=$(command -v tr)
for tool in diff mktemp rm; do
    ln -s -- "$(command -v "$tool")" "$symbol_bin/$tool"
done
cat > "$symbol_bin/tool" <<'SHIM'
#!/bin/sh
set -u
tool=${0##*/}
stage=$tool
bad_args() {
    printf 'unexpected-tool-arguments:%s\n' "$tool" >&2
    exit 97
}
owned_input() {
    [ "$#" -le 1 ] || bad_args
    if [ "$#" -eq 1 ]; then
        case "$1" in "$SDK_TEST_CASE"/*) ;; *) bad_args ;; esac
        [ -f "$1" ] || bad_args
    fi
}
case "$tool" in
    nm)
        [ "$#" -eq 3 ] || bad_args
        [ "$1" = -D ] && [ "$2" = --defined-only ] &&
            [ "$3" = "$SDK_TEST_LIBRARY" ] || bad_args
        printf '%s\n' '0000000000001000 T zuptsdk_alpha@@ZUPT_SDK_1.0'
        if [ "$SDK_TEST_CASE_NAME" != missing ]; then
            printf '%s\n' '0000000000001010 T zuptsdk_beta@@ZUPT_SDK_1.0'
        fi
        if [ "$SDK_TEST_CASE_NAME" = leaked ]; then
            printf '%s\n' '0000000000001020 T private_hidden'
        fi
        status=0
        ;;
    awk)
        [ "$#" -ge 1 ] && [ "$1" = '$2 == "T" { print $3 }' ] || bad_args
        shift
        owned_input "$@"
        status=0
        "$SDK_TEST_REAL_AWK" '$2 == "T" { print $3 }' "$@" || status=$?
        ;;
    sed)
        [ "$#" -ge 1 ] && [ "$1" = 's/@.*//' ] || bad_args
        shift
        owned_input "$@"
        status=0
        "$SDK_TEST_REAL_SED" 's/@.*//' "$@" || status=$?
        ;;
    sort)
        owned_input "$@"
        count=0
        if [ -f "$SDK_TEST_CASE/sort-count" ]; then
            read -r count < "$SDK_TEST_CASE/sort-count"
        fi
        count=$((count + 1))
        printf '%s\n' "$count" > "$SDK_TEST_CASE/sort-count"
        case "$count" in
            1) stage=export-sort ;;
            2) stage=decl-sort ;;
            *) bad_args ;;
        esac
        status=0
        "$SDK_TEST_REAL_SORT" "$@" || status=$?
        ;;
    grep)
        [ "$#" -ge 1 ] || bad_args
        case "$1" in
            '^        zuptsdk_')
                [ "$#" -eq 2 ] && [ "$2" = "$SDK_TEST_CASE/symbols.map" ] || bad_args
                stage=decl-grep
                ;;
            -v)
                [ "$#" -eq 3 ] && [ "$2" = '^zuptsdk_' ] || bad_args
                owned_input "$3"
                stage=reject-grep
                ;;
            *) bad_args ;;
        esac
        status=0
        "$SDK_TEST_REAL_GREP" "$@" || status=$?
        ;;
    tr)
        [ "$#" -eq 2 ] && [ "$1" = -d ] && [ "$2" = ' ;' ] || bad_args
        status=0
        "$SDK_TEST_REAL_TR" "$@" || status=$?
        ;;
    unexpected-cc)
        printf 'unexpected-build\n' >> "$SDK_TEST_CASE/trace"
        printf 'unexpected-build\n' >&2
        exit 98
        ;;
    *) bad_args ;;
esac
real_status=$status
if [ "$SDK_TEST_FAULT" = "$stage" ]; then
    # Forward the complete real output before failing. Reject grep normally
    # returns 1 here; that legitimate no-match must not hide its injected error.
    if [ "$stage" = reject-grep ]; then expected=1; else expected=0; fi
    if [ "$real_status" -eq "$expected" ]; then
        status=73
        printf 'sdk-symbol-fault:%s:73:real=%s\n' "$stage" "$real_status" >&2
    fi
fi
printf '%s:%s:real=%s\n' "$stage" "$status" "$real_status" >> "$SDK_TEST_CASE/trace"
exit "$status"
SHIM
chmod +x "$symbol_bin/tool"
for tool in nm awk sed sort grep tr unexpected-cc; do
    ln -s tool "$symbol_bin/$tool"
done

symbol_case() {
    local name=$1 fault=$2 expected=$3 case_dir="$work/symbol-$1"
    local status=0 ok=1 pass_count=0 expected_real=0
    mkdir -p "$case_dir/tmp"
    printf '%s\n' 'sdk symbol fixture; never compile' > "$case_dir/prebuilt.so"
    # Independent literal declarations, not derived from nm or target output.
    cat > "$case_dir/symbols.map" <<'MAP'
ZUPT_SDK_1.0 {
    global:
        zuptsdk_alpha;
        zuptsdk_beta;
    local:
        *;
};
MAP
    : > "$case_dir/trace"
    (
        cd -- "$case_dir"
        env -i PATH="$symbol_bin" LC_ALL=C TMPDIR="$case_dir/tmp" \
            SDK_TEST_CASE="$case_dir" SDK_TEST_CASE_NAME="$name" \
            SDK_TEST_LIBRARY="$case_dir/prebuilt.so" SDK_TEST_FAULT="$fault" \
            SDK_TEST_REAL_AWK="$real_awk" SDK_TEST_REAL_SED="$real_sed" \
            SDK_TEST_REAL_SORT="$real_sort" SDK_TEST_REAL_GREP="$real_grep" \
            SDK_TEST_REAL_TR="$real_tr" \
            "$make_bin" --no-print-directory -rR -f "$root/sdk/Makefile.sdk" \
            -o "$case_dir/prebuilt.so" "SDK_SHARED=$case_dir/prebuilt.so" \
            "SDK_MAP=$case_dir/symbols.map" "SDK_BUILD_DIR=$case_dir/build" \
            "CC=$symbol_bin/unexpected-cc" Q=@ sdk-verify-symbols
    ) > "$case_dir/stdout" 2> "$case_dir/stderr" || status=$?
    if [[ $status != "$expected" ]]; then
        printf '%s: expected make status %s, got %s\n' "$name" "$expected" "$status" >&2
        ok=0
    fi
    pass_count=$("$real_grep" -Fc '  PASS: no symbol leakage and all declared symbols are exported' \
        "$case_dir/stdout") || [[ $? == 1 ]] || ok=0
    if [[ $expected == 0 ]]; then
        [[ $pass_count == 1 && ! -s $case_dir/stderr ]] || ok=0
    else
        [[ $pass_count == 0 ]] || ok=0
    fi
    if [[ -n $fault ]]; then
        [[ $fault != reject-grep ]] || expected_real=1
        "$real_grep" -Fxq "sdk-symbol-fault:$fault:73:real=$expected_real" \
            "$case_dir/stderr" || ok=0
        "$real_grep" -Fxq "$fault:73:real=$expected_real" \
            "$case_dir/trace" || ok=0
    fi
    if "$real_grep" -Eq 'unexpected-(build|tool-arguments)' \
        "$case_dir/trace" "$case_dir/stderr"; then
        ok=0
    fi
    [[ $(< "$case_dir/prebuilt.so") == 'sdk symbol fixture; never compile' ]] || ok=0
    rmdir -- "$case_dir/tmp" || ok=0
    if [[ $ok != 1 ]]; then
        printf '%s: symbol-target stdout/stderr/trace follow\n' "$name" >&2
        cat "$case_dir/stdout" "$case_dir/stderr" "$case_dir/trace" >&2
    fi
    [[ $ok == 1 ]]
}
label='sdk symbol target accepts the exact declared exports'
check symbol_case clean '' 0
for fault in nm awk sed export-sort decl-grep tr decl-sort reject-grep; do
    label="sdk symbol target rejects $fault failure after complete output"
    check symbol_case "$fault" "$fault" 2
done
for name in missing leaked; do
    label="sdk symbol target rejects $name exports"
    check symbol_case "$name" '' 2
done
printf 'SUMMARY: PASS=%d FAIL=%d\n' "$passed" "$failed"
((failed == 0))
