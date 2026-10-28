#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Warning-screen status controls only; these mocks do not analyze Jasmin.
set -eu

case "${0##*/}" in
    jasmin-warning-compiler)
        if [ "${1:-}" = -version ]; then
            printf 'Jasmin Compiler 2026.09.0\n'
            exit 0
        fi
        [ "$#" -eq 4 ] && [ "$1" = -wall ] && [ "$2" = -o ] || exit 91
        printf '.text\n' >"$3"
        if [ "$JASMIN_WARNING_CASE" = warning ]; then
            printf 'warning: synthetic compiler diagnostic\n'
        else
            printf 'synthetic compiler output without a warning\n'
        fi
        exit 0 ;;
    jasmin-warning-version)
        [ "${1:-}" = --version ] || exit 92
        printf 'Jasmin Compiler 2026.09.0\n'
        exit 0 ;;
    jasmin-warning-downstream)
        printf 'downstream compiler reached\n' >"$JASMIN_WARNING_MARKER"
        printf 'BLOCKED: intentional downstream mock compiler, not a source analysis\n' >&2
        exit 43 ;;
    grep)
        [ "$#" -eq 3 ] && [ "$1" = -Eiq ] &&
            [ "$2" = '(^|[[:space:]])warning(:|[[:space:]])' ] || exit 93
        case "$3" in
            */zupt_aes_ctr-compile.log) ;;
            *) exit 94 ;;
        esac
        case "$JASMIN_WARNING_CASE" in
            clean) exit 1 ;;
            warning) exit 0 ;;
            scanner-error)
                printf 'synthetic warning scanner failed with status 2\n' >&2
                exit 2 ;;
            scanner-unavailable)
                printf 'synthetic warning scanner failed with status 127\n' >&2
                exit 127 ;;
            *) exit 95 ;;
        esac ;;
esac

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
analysis_script=${JASMIN_SOURCE_SCRIPT:-$repo_root/tests/test_jasmin_source.sh}
self="$repo_root/tests/test_jasmin_source_wrapper.sh"
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-jasmin-warning-wrapper.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for helper in jasmin-warning-compiler jasmin-warning-version jasmin-warning-downstream grep; do
    ln -s "$self" "$test_tmp/$helper"
done

failures=0
for test_case in clean warning scanner-error scanner-unavailable; do
    case "$test_case" in
        clean) expected=43 ;;
        warning) expected=1 ;;
        scanner-error) expected=2 ;;
        scanner-unavailable) expected=127 ;;
    esac
    marker="$test_tmp/$test_case.downstream"
    actual=0
    PATH="$test_tmp:$PATH" JASMIN_WARNING_CASE="$test_case" JASMIN_WARNING_MARKER="$marker" \
        JASMINC="$test_tmp/jasmin-warning-compiler" \
        JASMIN_CT="$test_tmp/jasmin-warning-version" JASMIN_SAFETY="$test_tmp/jasmin-warning-version" \
        CC="$test_tmp/jasmin-warning-downstream" sh "$analysis_script" \
        >"$test_tmp/$test_case.log" 2>&1 || actual=$?
    failures_before=$failures
    if [ "$actual" -ne "$expected" ]; then
        printf 'FAIL: %s returned %s, expected %s\n' "$test_case" "$actual" "$expected" >&2
        failures=$((failures + 1))
    fi
    if [ "$test_case" = clean ]; then
        if [ ! -f "$marker" ]; then
            printf 'FAIL: clean warning scan did not reach the downstream sentinel\n' >&2
            failures=$((failures + 1))
        fi
    elif [ -f "$marker" ]; then
        printf 'FAIL: %s reached downstream work after a rejected warning scan\n' "$test_case" >&2
        failures=$((failures + 1))
    fi
    case "$test_case" in
        warning)
            if ! grep -Fq 'FAIL: zupt_aes_ctr-compile emitted a warning' "$test_tmp/$test_case.log"; then
                printf 'FAIL: warning rejection diagnostic is missing or cannot be read\n' >&2
                failures=$((failures + 1))
            fi ;;
        scanner-error|scanner-unavailable)
            if ! grep -Fq "FAIL: zupt_aes_ctr-compile warning scan exited $expected" "$test_tmp/$test_case.log"; then
                printf 'FAIL: scanner failure diagnostic is missing or cannot be read\n' >&2
                failures=$((failures + 1))
            fi ;;
    esac
    pass_status=0
    grep -Fq 'PASS: five selected Jasmin sources' "$test_tmp/$test_case.log" || pass_status=$?
    if [ "$pass_status" -ne 1 ]; then
        printf 'FAIL: a diagnostic control printed source-analysis success or its result check failed\n' >&2
        failures=$((failures + 1))
    fi
    if [ "$failures" -ne "$failures_before" ]; then
        cat "$test_tmp/$test_case.log" >&2
    else
        printf 'PASS: synthetic Jasmin warning-scan %s case\n' "$test_case"
    fi
done
if [ "$failures" -ne 0 ]; then
    printf 'FAIL: warning-screen controls found %s failures\n' "$failures" >&2
    exit 1
fi
printf 'PASS: four warning-screen status controls; no Jasmin analysis was executed\n'
