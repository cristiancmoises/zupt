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

# Model Darwin's first-header feature selection without an Apple SDK. Hide the
# Linux prototype so it cannot mask a missing or too-late Darwin feature macro.
mkdir "$test_tmp/darwin-headers"
cat > "$test_tmp/darwin-headers/feature-model.h" <<'HEADER'
#ifndef ZUPT_TEST_DARWIN_FEATURES
#define ZUPT_TEST_DARWIN_FEATURES
#if defined(_DARWIN_C_SOURCE) || (!defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE))
#define ZUPT_TEST_DARWIN_EXTENSIONS 1
#else
#define ZUPT_TEST_DARWIN_EXTENSIONS 0
#endif
#endif
HEADER
for first_header in stdio stdint; do
    printf '#include "feature-model.h"\n#include_next <%s.h>\n' "$first_header" \
        > "$test_tmp/darwin-headers/$first_header.h"
done
cat > "$test_tmp/darwin-headers/stdlib.h" <<'HEADER'
#include "feature-model.h"
#define mkdtemp zupt_test_hidden_mkdtemp
#include_next <stdlib.h>
#undef mkdtemp
HEADER
cat > "$test_tmp/darwin-headers/unistd.h" <<'HEADER'
#include "feature-model.h"
#define mkdtemp zupt_test_hidden_mkdtemp
#include_next <unistd.h>
#undef mkdtemp
#if ZUPT_TEST_DARWIN_EXTENSIONS
char *mkdtemp(char *);
#endif
HEADER
cat > "$test_tmp/darwin-headers/fcntl.h" <<'HEADER'
#include "feature-model.h"
#include_next <fcntl.h>
#if !ZUPT_TEST_DARWIN_EXTENSIONS
#undef O_NOFOLLOW
#endif
HEADER
for first_header in stdio stdint fcntl; do
  for feature_case in posix-missing posix-late xopen-missing xopen-late; do
    {
        printf '#undef _DARWIN_C_SOURCE\n'
        case $feature_case in
            posix-*) printf '#define _POSIX_C_SOURCE 200809L\n' ;;
            xopen-*) printf '#define _XOPEN_SOURCE 700\n' ;;
        esac
        printf '#include <%s.h>\n' "$first_header"
        case $feature_case in *-late) printf '#define _DARWIN_C_SOURCE 1\n' ;; esac
        printf '#include <stdlib.h>\n#include <unistd.h>\n#include <fcntl.h>\n'
        printf 'int main(void) { char path[] = "probe.XXXXXX"; return mkdtemp(path) == NULL || O_NOFOLLOW == 0; }\n'
    } > "$test_tmp/$feature_case.c"
    # shellcheck disable=SC2086
    if "${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
        -D__APPLE__=1 -Werror=implicit-function-declaration \
        -isystem "$test_tmp/darwin-headers" -fsyntax-only "$test_tmp/$feature_case.c" \
        > "$test_tmp/$feature_case.log" 2>&1; then
        printf 'FAIL: modeled Darwin headers exposed mkdtemp with %s feature macro after %s\n' \
            "$feature_case" "$first_header" >&2
        exit 1
    fi
    grep -F 'mkdtemp' "$test_tmp/$feature_case.log" >/dev/null
    grep -E 'implicit.*declaration|undeclared function' "$test_tmp/$feature_case.log" >/dev/null
    if ! grep -E 'error:.*(O_NOFOLLOW.*undeclared|undeclared.*O_NOFOLLOW)' \
        "$test_tmp/$feature_case.log" >/dev/null; then
        printf 'FAIL: modeled Darwin headers exposed O_NOFOLLOW with %s feature macro after %s\n' \
            "$feature_case" "$first_header" >&2
        exit 1
    fi
  done
done
# This is header-visibility coverage, not a native macOS compilation.
for fuzz_source in tests/fuzz_format.c tests/fuzz_decompress.c tests/test_fuzz_format_harness.c; do
    # shellcheck disable=SC2086
    "${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
        -D__APPLE__=1 -Werror=implicit-function-declaration \
        -I"$test_root/include" -I"$test_root/src" \
        -isystem "$test_tmp/darwin-headers" -fsyntax-only "$fuzz_source"
done
printf 'PASS: modeled Darwin mkdtemp/O_NOFOLLOW visibility covers fuzz harnesses, fixture and POSIX/XOPEN controls\n'

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

# Replace the checked input at the actual open call, without a timing race.
# Include the fixture after the adapters to support non-GNU linkers too.
cat > "$test_tmp/capture-race.c" <<'CAPTURE_RACE'
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
FILE *capture_fopen(const char *, const char *);
int capture_openat(int, const char *, int, ...);
int capture_open(const char *, int, ...);
static int replaced;
static void replace_input(void) {
    const char *mode = getenv("ZUPT_CAPTURE_RACE");
    const char *path = getenv("ZUPT_CAPTURE_TARGET");
    const char *foreign = getenv("ZUPT_CAPTURE_FOREIGN");
    if (!mode || replaced) return;
    replaced = 1;
    if (!strcmp(mode, "ancestor")) {
        const char *directory = getenv("ZUPT_CAPTURE_DIRECTORY");
        if (rename(directory, getenv("ZUPT_CAPTURE_MOVED")) || mkdir(directory, 0700) ||
            link(foreign, path)) _Exit(126);
    } else {
        if (unlink(path)) _Exit(126);
        if ((!strcmp(mode, "symlink") && symlink(foreign, path)) ||
            (!strcmp(mode, "mode") && link(foreign, path)) ||
            (!strcmp(mode, "fifo") && mkfifo(path, 0600))) _Exit(126);
    }
    fprintf(stderr, "CAPTURE INTERLEAVING: %s\n", mode);
}
FILE *capture_fopen(const char *path, const char *mode) {
    const char *target = getenv("ZUPT_CAPTURE_TARGET");
    if (target && !strcmp(path, target) && !strcmp(mode, "rb")) replace_input();
    return fopen(path, mode);
}
int capture_open(const char *path, int flags, ...) {
    const char *target = getenv("ZUPT_CAPTURE_TARGET");
    if (target && !strcmp(path, target)) replace_input();
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, int);
        va_end(args);
        return open(path, flags, mode);
    }
    return open(path, flags);
}
int capture_openat(int directory, const char *path, int flags, ...) {
    const char *target = getenv("ZUPT_CAPTURE_TARGET");
    const char *leaf = target ? strrchr(target, '/') : NULL;
    if (leaf && !strcmp(path, leaf + 1)) replace_input();
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, int);
        va_end(args);
        return openat(directory, path, flags, mode);
    }
    return openat(directory, path, flags);
}
#define fopen capture_fopen
#define open capture_open
#define openat capture_openat
#define main capture_fixture_main
int capture_fixture_main(int, char **);
#include "tests/test_fuzz_format_harness.c"
#undef main
int main(int argc, char **argv) {
    if (signal(SIGALRM, SIG_DFL) == SIG_ERR) return 126;
    alarm(3);
    return capture_fixture_main(argc, argv);
}
CAPTURE_RACE
# Model headers which select a newer POSIX level before including the fixture.
for fixture_source in tests/test_fuzz_format_harness.c capture-race.c; do
    cat > "$test_tmp/posix-level.c" <<'POSIX_LEVEL'
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 202405L
POSIX_LEVEL
    printf '#include "%s"\n' "$fixture_source" >> "$test_tmp/posix-level.c"
    cat >> "$test_tmp/posix-level.c" <<'POSIX_LEVEL'
#if _POSIX_C_SOURCE < 202405L
#error Fixture must preserve the POSIX level selected by its caller or headers
#endif
POSIX_LEVEL
    # shellcheck disable=SC2086
    TMPDIR="$test_tmp" "${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
        -Werror -I"$test_root" -I"$test_tmp" -fsyntax-only "$test_tmp/posix-level.c"
done
printf 'PASS: fixture and capture translation unit preserve a newer POSIX level\n'
# Keep compiler scratch separate from spaced runtime inputs, including LTO jobs.
# shellcheck disable=SC2086
TMPDIR="$test_tmp" "${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    -D__APPLE__=1 -I"$test_root" -isystem "$test_tmp/darwin-headers" \
    -fsyntax-only "$test_tmp/capture-race.c"
printf 'PASS: modeled Darwin O_NOFOLLOW visibility covers the capture translation unit\n'
# shellcheck disable=SC2086
TMPDIR="$test_tmp" "${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    -I"$test_root" "$test_tmp/capture-race.c" ${LDFLAGS:-} ${LDLIBS:-} \
    -o "$test_tmp/capture-race"
for capture_race in symlink mode fifo ancestor; do
    capture_directory="$TMPDIR/capture-$capture_race"
    mkdir -m 700 "$capture_directory"
    (umask 077; printf 'original mutated input\n' > "$capture_directory/input.zupt")
    (umask 077; printf 'foreign fixture bytes\n' > "$test_tmp/foreign-$capture_race")
    if [ "$capture_race" = mode ]; then chmod 644 "$test_tmp/foreign-$capture_race"; fi
    capture_log="$test_tmp/capture-$capture_race.log"
    capture_status=0
    ZUPT_FUZZ_TEST_MODE=accept ZUPT_FUZZ_TEST_PATH_LOG="$capture_log" \
        ZUPT_CAPTURE_RACE="$capture_race" \
        ZUPT_CAPTURE_TARGET="$capture_directory/input.zupt" \
        ZUPT_CAPTURE_DIRECTORY="$capture_directory" \
        ZUPT_CAPTURE_MOVED="$capture_directory-moved" \
        ZUPT_CAPTURE_FOREIGN="$test_tmp/foreign-$capture_race" \
        "$test_tmp/capture-race" list "$capture_directory/input.zupt" \
        > "$test_tmp/capture-$capture_race.stdout" \
        2> "$test_tmp/capture-$capture_race.stderr" || capture_status=$?
    grep -Fx "CAPTURE INTERLEAVING: $capture_race" \
        "$test_tmp/capture-$capture_race.stderr" >/dev/null
    if [ "$capture_race" = ancestor ]; then
        if [ "$capture_status" != 0 ] ||
            ! cmp -s "$capture_log.input" "$capture_directory-moved/input.zupt"; then
            echo 'FAIL: fixture input must remain bound to the original private directory' >&2
            exit 1
        fi
    elif [ "$capture_status" != 127 ] || [ -e "$capture_log.input" ]; then
        printf 'FAIL: fixture accepted replacement %s input (status %s)\n' \
            "$capture_race" "$capture_status" >&2
        exit 1
    fi
done
printf 'PASS: fixture capture rejects symlink/mode/FIFO replacements and pins its original directory\n'

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
