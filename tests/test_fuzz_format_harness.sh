#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu
case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*)
        echo 'SKIP: POSIX fork/waitpid harness regression is unavailable on Windows'
        exit 0
        ;;
esac
test_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM
mkdir "$test_tmp/mutations with spaces"
cd "$test_root"

# Deliberately use the real harness and its child-execution path.
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    tests/fuzz_format.c ${LDFLAGS:-} ${LDLIBS:-} -o "$test_tmp/harness"
# Instrument the harness itself so the exact 16-byte mutation boundary cannot
# turn either fixed-size run operation into a zero-divisor calculation.
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    -fsanitize=undefined -fno-sanitize-recover=undefined \
    tests/fuzz_format.c ${LDFLAGS:-} ${LDLIBS:-} -o "$test_tmp/harness-ubsan"
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    tests/test_fuzz_format_harness.c ${LDFLAGS:-} ${LDLIBS:-} -o "$test_tmp/child"
# Only this controlled child is instrumented here. ASan diagnostic cases below
# are synthetic classification tests, not evidence of an ASan codec run.
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    -fsanitize=undefined -fno-sanitize-recover=undefined \
    tests/test_fuzz_format_harness.c ${LDFLAGS:-} ${LDLIBS:-} -o "$test_tmp/ubsan-child"
# Exercise spaced mutation paths at runtime without changing compiler scratch.
TMPDIR="$test_tmp/mutations with spaces"
export TMPDIR
printf 'seed1234' > "$test_tmp/seed"
printf '0123456789abcdef' > "$test_tmp/seed-16"

check_log() {
    if ! grep -F "$2" "$1" >/dev/null; then
        printf 'FAIL: missing expected harness result: %s\n' "$2" >&2
        exit 1
    fi
}

for test_mode in accept reject; do
    ZUPT_FUZZ_TEST_MODE=$test_mode "$test_tmp/harness" 1 "$test_tmp/child" \
        "$test_tmp/seed" > "$test_tmp/$test_mode.log" 2>&1
    check_log "$test_tmp/$test_mode.log" 'completed:         1/1'
    check_log "$test_tmp/$test_mode.log" 'sanitizer findings:0'
    check_log "$test_tmp/$test_mode.log" 'harness failures:  0'
done
check_log "$test_tmp/accept.log" 'accepts:            1'
check_log "$test_tmp/reject.log" 'errors (rejected):  1'
if ! ZUPT_FUZZ_TEST_MODE=accept "$test_tmp/harness-ubsan" 1 "$test_tmp/child" \
    "$test_tmp/seed-16" > "$test_tmp/boundary-16.log" 2>&1; then
    cat "$test_tmp/boundary-16.log" >&2
    echo 'FAIL: exact 16-byte mutation boundary failed under UBSan' >&2
    exit 1
fi
check_log "$test_tmp/boundary-16.log" 'completed:         1/1'
check_log "$test_tmp/boundary-16.log" 'sanitizer findings:0'
check_log "$test_tmp/boundary-16.log" 'harness failures:  0'
for test_mode in asan lsan ubsan-name ubsan binary-prefix diagnostic-success signal too-much-output; do
    if ZUPT_FUZZ_TEST_MODE=$test_mode "$test_tmp/harness" 1 "$test_tmp/child" \
        "$test_tmp/seed" > "$test_tmp/$test_mode.log" 2>&1; then
        printf 'FAIL: harness accepted %s finding\n' "$test_mode" >&2
        exit 1
    fi
    case $test_mode in
        signal) check_log "$test_tmp/$test_mode.log" 'CRASHES (signal):   1' ;;
        too-much-output) check_log "$test_tmp/$test_mode.log" 'harness failures:  1' ;;
        *)
            check_log "$test_tmp/$test_mode.log" 'Sanitizer diagnostic from child:'
            check_log "$test_tmp/$test_mode.log" 'sanitizer findings:1'
            check_log "$test_tmp/$test_mode.log" 'harness failures:  0'
            check_log "$test_tmp/$test_mode.log" 'CRASHES (signal):   0'
            ;;
    esac
done
if ZUPT_FUZZ_TEST_MODE=ubsan-real "$test_tmp/harness" 1 "$test_tmp/ubsan-child" \
    "$test_tmp/seed" > "$test_tmp/ubsan-real.log" 2>&1; then
    echo 'FAIL: harness accepted instrumented UBSan failure' >&2
    exit 1
fi
check_log "$test_tmp/ubsan-real.log" 'runtime error: division by zero'
check_log "$test_tmp/ubsan-real.log" 'sanitizer findings:1'
check_log "$test_tmp/ubsan-real.log" 'harness failures:  0'
check_log "$test_tmp/ubsan-real.log" 'CRASHES (signal):   0'
if "$test_tmp/harness" 1 "$test_tmp/missing-child" "$test_tmp/seed" \
    > "$test_tmp/exec-failure.log" 2>&1; then
    echo 'FAIL: harness accepted child execution failure' >&2
    exit 1
fi
check_log "$test_tmp/exec-failure.log" 'harness failures:  1'
check_log "$test_tmp/exec-failure.log" 'Child execution failed with status 127'

# Only this owned scratch is used for temporary-input lifetime checks.
for test_mode in accept reject; do
    witness="$test_tmp/private-$test_mode.path"
    if ! ZUPT_FUZZ_TEST_PATH_LOG=$witness ZUPT_FUZZ_TEST_MODE=$test_mode \
        "$test_tmp/harness" 2 "$test_tmp/child" "$test_tmp/seed" \
        > "$test_tmp/private-$test_mode.log" 2>&1; then
        cat "$test_tmp/private-$test_mode.log" >&2
        printf 'FAIL: private-input %s execution or lifetime\n' "$test_mode" >&2
        exit 1
    fi
    check_log "$test_tmp/private-$test_mode.log" 'completed:         2/2'
    test "$(wc -l < "$witness")" -eq 2
    IFS= read -r private_path < "$witness"
    case $private_path in "$TMPDIR"/*/input.zupt) ;; *) exit 1 ;; esac
    test ! -e "$private_path"
    test ! -e "${private_path%/*}"
done
IFS= read -r accept_path < "$test_tmp/private-accept.path"
IFS= read -r reject_path < "$test_tmp/private-reject.path"
test "$accept_path" != "$reject_path"
for test_mode in asan diagnostic-success signal too-much-output; do
    witness="$test_tmp/retained-$test_mode.path"
    if ZUPT_FUZZ_TEST_PATH_LOG=$witness ZUPT_FUZZ_TEST_MODE=$test_mode \
        "$test_tmp/harness" 2 "$test_tmp/child" "$test_tmp/seed" \
        > "$test_tmp/retained-$test_mode.log" 2>&1; then
        printf 'FAIL: retained-input case accepted %s\n' "$test_mode" >&2
        exit 1
    fi
    check_log "$test_tmp/retained-$test_mode.log" 'completed:         1/2'
    test "$(wc -l < "$witness")" -eq 1
    IFS= read -r retained_path < "$witness"
    case $retained_path in "$TMPDIR"/*/input.zupt) ;; *) exit 1 ;; esac
    check_log "$test_tmp/retained-$test_mode.log" "Retained fuzz input: $retained_path"
    cmp "$retained_path" "$witness.input"
done
# An execution failure still leaves the complete attempted input for replay.
exec_input=$(sed -n 's/^Retained fuzz input: //p' "$test_tmp/exec-failure.log")
case $exec_input in "$TMPDIR"/*/input.zupt) ;; *) exit 1 ;; esac
ZUPT_FUZZ_TEST_MODE=accept ZUPT_FUZZ_TEST_PATH_LOG="$test_tmp/exec-witness.path" \
    "$test_tmp/child" list "$exec_input"
cmp "$exec_input" "$test_tmp/exec-witness.path.input"

# Cleanup errors must not turn an accepted child result into a passing test.
for test_mode in remove-input extra-entry; do
    witness="$test_tmp/cleanup-$test_mode.path"
    requested=1
    if test "$test_mode" = remove-input; then requested=2; fi
    if ZUPT_FUZZ_TEST_PATH_LOG=$witness ZUPT_FUZZ_TEST_MODE=$test_mode \
        "$test_tmp/harness" "$requested" "$test_tmp/child" "$test_tmp/seed" \
        > "$test_tmp/cleanup-$test_mode.log" 2>&1; then
        printf 'FAIL: harness ignored %s cleanup failure\n' "$test_mode" >&2
        exit 1
    fi
    check_log "$test_tmp/cleanup-$test_mode.log" "completed:         1/$requested"
    check_log "$test_tmp/cleanup-$test_mode.log" 'accepts:            1'
    check_log "$test_tmp/cleanup-$test_mode.log" 'errors (rejected):  0'
    check_log "$test_tmp/cleanup-$test_mode.log" 'sanitizer findings:0'
    check_log "$test_tmp/cleanup-$test_mode.log" 'CRASHES (signal):   0'
    test "$(wc -l < "$witness")" -eq 1
    IFS= read -r private_path < "$witness"
    case $private_path in "$TMPDIR"/*/input.zupt) ;; *) exit 1 ;; esac
    test ! -e "$private_path"
    test -d "${private_path%/*}"
    if test "$test_mode" = remove-input; then
        check_log "$test_tmp/cleanup-$test_mode.log" 'harness failures:  2'
        check_log "$test_tmp/cleanup-$test_mode.log" 'Harness mutation input cleanup'
        check_log "$test_tmp/cleanup-$test_mode.log" 'Fuzz input unavailable; retained directory:'
        if grep -F 'Retained fuzz input:' "$test_tmp/cleanup-$test_mode.log" >/dev/null; then
            echo 'FAIL: nonexistent input reported as retained' >&2
            exit 1
        fi
    else
        check_log "$test_tmp/cleanup-$test_mode.log" 'harness failures:  1'
        check_log "$test_tmp/cleanup-$test_mode.log" 'Harness temporary directory cleanup'
        check_log "$test_tmp/cleanup-$test_mode.log" "Retained fuzz directory: ${private_path%/*}"
        test "$(cat "$private_path.extra")" = 'owned fixture'
        if grep -F 'Retained fuzz input:' "$test_tmp/cleanup-$test_mode.log" >/dev/null; then
            echo 'FAIL: directory-only retention reported as an input' >&2
            exit 1
        fi
    fi
done
# A non-directory TMPDIR must fail before running the child or deleting it.
printf 'owned sentinel\n' > "$test_tmp/not-directory"
if TMPDIR="$test_tmp/not-directory" ZUPT_FUZZ_TEST_MODE=accept \
    ZUPT_FUZZ_TEST_PATH_LOG="$test_tmp/no-child.path" \
    "$test_tmp/harness" 1 "$test_tmp/child" "$test_tmp/seed" \
    > "$test_tmp/temp-failure.log" 2>&1; then
    echo 'FAIL: invalid TMPDIR accepted' >&2
    exit 1
fi
check_log "$test_tmp/temp-failure.log" 'Harness temporary directory'
test ! -e "$test_tmp/no-child.path"
test "$(cat "$test_tmp/not-directory")" = 'owned sentinel'
printf 'PASS: valid/rejected child results and fail-closed diagnostics, signals, exec, output bound\n'
printf 'PASS: exact 16-byte mutation boundary under UBSan\n'
printf 'PASS: instrumented UBSan child; ASan/LSan cases are synthetic classification tests\n'
printf 'PASS: private inputs, success cleanup, exact failure retention and invalid TMPDIR\n'
printf 'PASS: child execution and cleanup failures preserve their explicit input disposition\n'
