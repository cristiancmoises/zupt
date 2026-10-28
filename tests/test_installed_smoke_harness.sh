#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

set -Eeuo pipefail
export LC_ALL=C
umask 077
ulimit -c 0

# These tool shims preserve real output and change only the selected producer's
# status. A restricted PATH also exercises the shasum fallback without Perl.
if [[ ${ZUPT_SMOKE_TOOL_CHILD:-0} == 1 ]]; then
    tool=${0##*/}
    case $tool in
        sha256sum|shasum) real_tool=$ZUPT_SMOKE_REAL_HASH ;;
        find) real_tool=$ZUPT_SMOKE_REAL_FIND ;;
        sort) real_tool=$ZUPT_SMOKE_REAL_SORT ;;
        *) printf 'HARNESS SETUP FAILURE: unknown tool shim\n' >&2; exit 125 ;;
    esac
    if [[ $tool == shasum ]]; then
        [[ ${1:-} == -a && ${2:-} == 256 ]] || {
            printf 'HARNESS SETUP FAILURE: unexpected shasum arguments\n' >&2
            exit 125
        }
        shift 2
    fi
    if [[ ( $tool == sha256sum || $tool == shasum ) &&
          $ZUPT_SMOKE_REAL_HASH_KIND == shasum ]]; then
        set -- -a 256 "$@"
    fi
    tree=
    case $PWD in
        */plain-out/*) tree=extracted ;;
        */input) tree=original ;;
    esac
    if [[ -z $tree ||
          ( $ZUPT_SMOKE_TOOL_TREE != both && $ZUPT_SMOKE_TOOL_TREE != "$tree" ) ||
          $ZUPT_SMOKE_TOOL_FAULT != "$tool" ]]; then
        exec "$real_tool" "$@"
    fi
    printf 'SMOKE-HASH-FAULT: %s %s %s\n' \
        "$tool" "$ZUPT_SMOKE_TOOL_MODE" "$ZUPT_SMOKE_TOOL_TREE" >&2
    if [[ $ZUPT_SMOKE_TOOL_MODE == plausible ]]; then
        if ! "$real_tool" "$@"; then
            printf 'HARNESS SETUP FAILURE: real tool failed\n' >&2
            exit 125
        fi
    elif [[ $ZUPT_SMOKE_TOOL_MODE != empty ]]; then
        printf 'HARNESS SETUP FAILURE: unknown tool mode\n' >&2
        exit 125
    fi
    exit 73
fi

# The shim delegates all normal operations to the real CLI. Faults exercise
# the smoke test's process boundary, not the codec or sanitizer runtimes.
if [[ ${ZUPT_SMOKE_HARNESS_CHILD:-0} == 1 ]]; then
    boundary=
    case ${1:-} in
        --version) boundary=version ;;
        --help) boundary=help ;;
        --definitely-invalid-option) boundary=invalid-command ;;
        compress|test|extract)
            boundary=plain-$1
            for argument in "$@"; do
                case $argument in
                    */password.zupt) boundary=password-$1 ;;
                    incorrect-password) boundary=wrong-password; break ;;
                    */corrupt.zupt) boundary=corrupt; break ;;
                    */escape-out) boundary=destination-symlink; break ;;
                esac
            done
            ;;
    esac
    if [[ $boundary != "${ZUPT_SMOKE_FAULT_BOUNDARY:-}" ]]; then
        exec "$ZUPT_SMOKE_REAL_CLI" "$@"
    fi

    marker="SMOKE-HARNESS-FAULT: $boundary $ZUPT_SMOKE_FAULT_MODE"
    case $ZUPT_SMOKE_FAULT_MODE in
        status-0|status-2|status-127)
            printf '%s\n' "$marker" >&2
            if "$ZUPT_SMOKE_REAL_CLI" "$@"; then
                status=0
            else
                status=$?
            fi
            if [[ $status != 1 ]]; then
                printf 'HARNESS SETUP FAILURE: rejection returned %s\n' "$status" >&2
                exit 125
            fi
            exit "${ZUPT_SMOKE_FAULT_MODE#status-}"
            ;;
        unrelated-1)
            printf '%s\nunrelated execution failure\n' "$marker" >&2
            exit 1
            ;;
        term|segv)
            printf '%s\n' "$marker" >&2
            if [[ $ZUPT_SMOKE_FAULT_MODE == term ]]; then
                kill -TERM "$$"
            else
                kill -SEGV "$$"
            fi
            exit 125
            ;;
    esac

    if "$ZUPT_SMOKE_REAL_CLI" "$@"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$marker" >&2
    case $ZUPT_SMOKE_FAULT_MODE in
        asan) printf 'ERROR: AddressSanitizer: synthetic diagnostic\n' >&2 ;;
        lsan) printf 'ERROR: LeakSanitizer: synthetic diagnostic\n' >&2 ;;
        ubsan) printf 'UndefinedBehaviorSanitizer: synthetic diagnostic\n' >&2 ;;
        runtime) printf 'fixture.c:1:1: runtime error: synthetic diagnostic\n' >&2 ;;
        binary-prefix) printf '\000ERROR: AddressSanitizer: synthetic diagnostic\n' >&2 ;;
        *) printf 'unknown harness mode\n' >&2; exit 125 ;;
    esac
    exit "$status"
fi

[[ $# -eq 1 ]] || { printf 'Usage: %s /path/to/zupt\n' "$0" >&2; exit 2; }
candidate=$1
[[ -x $candidate ]] || { printf 'FAIL: real CLI is not executable\n' >&2; exit 1; }
real_cli=$(cd -- "$(dirname -- "$candidate")" && pwd -P)/$(basename -- "$candidate")
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
smoke=$repo_root/scripts/test-installed-zupt.sh
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-smoke-harness.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
cp -- "${BASH_SOURCE[0]}" "$work/shim"
chmod 700 "$work/shim"
export ZUPT_SMOKE_REAL_CLI=$real_cli ZUPT_SMOKE_HARNESS_CHILD=1

failures=0
checks=0
run_case() {
    local boundary=$1 mode=$2 expected=$3 status log
    log=$work/$boundary-$mode.log
    export ZUPT_SMOKE_FAULT_BOUNDARY=$boundary ZUPT_SMOKE_FAULT_MODE=$mode
    if bash "$smoke" "$work/shim" > "$log" 2>&1; then
        status=0
    else
        status=$?
    fi
    checks=$((checks + 1))
    printf 'CASE: %s/%s: smoke status %s\n' "$boundary" "$mode" "$status"
    cat -- "$log"
    if [[ $status != "$expected" ]] || \
       grep -aFq 'HARNESS SETUP FAILURE:' "$log" || \
       { [[ $expected == 0 ]] && ! grep -q '^PASS: installed ZUPT functional test suite$' "$log"; } || \
       { [[ $expected == 1 ]] && { ! grep -q '^FAIL:' "$log" || \
           ! grep -aFq "SMOKE-HARNESS-FAULT: $boundary $mode" "$log"; }; }; then
        printf 'FAIL: %s/%s: expected smoke status %s, got %s\n' "$boundary" "$mode" "$expected" "$status" >&2
        failures=$((failures + 1))
    else
        printf 'PASS: %s/%s\n' "$boundary" "$mode"
    fi
}

run_case none clean 0
case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*) signals=(); printf 'SKIP: POSIX signal fixtures on Windows\n' ;;
    *) signals=(term segv) ;;
esac
for boundary in invalid-command wrong-password corrupt destination-symlink; do
    for mode in status-0 status-2 status-127 unrelated-1 "${signals[@]}" asan lsan ubsan runtime; do
        run_case "$boundary" "$mode" 1
    done
done
for boundary in version help plain-compress plain-test plain-extract password-compress password-test password-extract; do
    run_case "$boundary" asan 1
done
for mode in lsan ubsan runtime binary-prefix; do
    run_case version "$mode" 1
done

# Use real archive operations in each case. Only hashing/sorting/enumeration
# tools are substituted; their successful output comes from the real tools.
unset ZUPT_SMOKE_HARNESS_CHILD
export ZUPT_SMOKE_REAL_HASH ZUPT_SMOKE_REAL_HASH_KIND ZUPT_SMOKE_REAL_FIND ZUPT_SMOKE_REAL_SORT
if ZUPT_SMOKE_REAL_HASH=$(command -v sha256sum); then
    ZUPT_SMOKE_REAL_HASH_KIND=sha256sum
else
    ZUPT_SMOKE_REAL_HASH=$(command -v shasum)
    ZUPT_SMOKE_REAL_HASH_KIND=shasum
fi
ZUPT_SMOKE_REAL_FIND=$(command -v find)
ZUPT_SMOKE_REAL_SORT=$(command -v sort)
tool_bash=$(command -v bash)
run_tool_case() {
    local checksum=$1 tool=$2 mode=$3 tree=$4 expected=$5 status log
    log=$work/$checksum-$tool-$mode-$tree.log
    if env PATH="$work/tools-$checksum" ZUPT_SMOKE_TOOL_CHILD=1 \
        ZUPT_SMOKE_TOOL_FAULT="$tool" ZUPT_SMOKE_TOOL_MODE="$mode" \
        ZUPT_SMOKE_TOOL_TREE="$tree" \
        "$tool_bash" "$smoke" "$real_cli" > "$log" 2>&1; then
        status=0
    else
        status=$?
    fi
    checks=$((checks + 1))
    printf 'CASE: %s/%s/%s/%s: smoke status %s\n' "$checksum" "$tool" "$mode" "$tree" "$status"
    cat -- "$log"
    if [[ $status != "$expected" ]] || \
       grep -aFq 'HARNESS SETUP FAILURE:' "$log" || \
       { [[ $expected == 0 ]] && ! grep -q '^PASS: installed ZUPT functional test suite$' "$log"; } || \
       { [[ $expected == 1 ]] && {
           ! grep -q '^FAIL:' "$log" || \
           ! grep -aFq "SMOKE-HASH-FAULT: $tool $mode $tree" "$log" || \
           grep -q '^PASS: installed ZUPT functional test suite$' "$log"; }; }; then
        printf 'FAIL: checksum boundary %s/%s/%s/%s: expected %s, got %s\n' \
            "$checksum" "$tool" "$mode" "$tree" "$expected" "$status" >&2
        failures=$((failures + 1))
    else
        printf 'PASS: checksum boundary %s/%s/%s/%s\n' "$checksum" "$tool" "$mode" "$tree"
    fi
}
for checksum in sha256sum shasum; do
    tools=$work/tools-$checksum
    mkdir -- "$tools"
    for name in bash basename cat chmod cmp dd diff dirname grep head id ln mkdir mktemp rm wc; do
        real_tool=$(command -v -- "$name")
        ln -s -- "$real_tool" "$tools/$name"
    done
    for name in "$checksum" find sort; do
        cp -- "${BASH_SOURCE[0]}" "$tools/$name"
        chmod 700 "$tools/$name"
    done
    run_tool_case "$checksum" none clean both 0
    run_tool_case "$checksum" "$checksum" empty both 1
    run_tool_case "$checksum" "$checksum" plausible original 1
    run_tool_case "$checksum" "$checksum" plausible extracted 1
    run_tool_case "$checksum" find plausible both 1
    run_tool_case "$checksum" sort plausible both 1
done

if (( failures != 0 )); then
    printf 'FAIL: installed-smoke harness: %s/%s checks failed\n' "$failures" "$checks" >&2
    exit 1
fi
printf 'PASS: installed-smoke harness: %s checks\n' "$checks"
