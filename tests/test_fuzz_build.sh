#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu
case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*)
        echo 'SKIP: archive fuzz harness requires POSIX temporary directories'
        exit 0
        ;;
esac
# A check run can reuse its already-built CLI for the plain STORE seed.
# The fuzz targets still compile their own sanitizer-instrumented core.
if test "${FUZZ_TEST_CLI+x}" = x; then
    if ! test -f "$FUZZ_TEST_CLI" || ! test -x "$FUZZ_TEST_CLI"; then
        printf 'FAIL: FUZZ_TEST_CLI must name an executable regular file\n' >&2
        exit 1
    fi
    case $FUZZ_TEST_CLI in
        /*) test_cli=$FUZZ_TEST_CLI ;;
        *) test_cli="$(pwd -P)/$FUZZ_TEST_CLI" ;;
    esac
fi
test_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_tmp=$(mktemp -d)
trap 'rm -rf -- "$test_tmp"' EXIT HUP INT TERM
set -- fuzz-build
if test "${FUZZ_TEST_CLI+x}" != x; then
    test_cli=$test_tmp/project/zupt
    set -- "$@" all
fi

# Exercise the real fuzz-build recipes without requiring AFL++ for a link
# regression. UBSan executes here; AFL coverage is a separate validation.
mkdir -p "$test_tmp/project/src" "$test_tmp/project/include" \
    "$test_tmp/project/sdk" "$test_tmp/project/tests"
cp "$test_root/Makefile" "$test_tmp/project/"
cp "$test_root/sdk/Makefile.sdk" "$test_tmp/project/sdk/"
cp "$test_root"/src/*.c "$test_root"/src/*.h "$test_tmp/project/src/"
cp "$test_root"/include/*.h "$test_tmp/project/include/"
cp "$test_root/tests/fuzz_decompress.c" "$test_root/tests/fuzz_vv_decompress.c" \
    "$test_tmp/project/tests/"
test_cflags="${CFLAGS:--O2 -g} -Wcast-align -Werror"
compiler_banner=$("${CC:-cc}" --version)
case $compiler_banner in
    *clang*)
        target_machine=$("${CC:-cc}" -dumpmachine)
        for object in zupt_sha256_shani vv_ans vv_simd vv_decoder; do
            # 'false' classifies a non-Clang driver without compiling with it.
            # The dry run must classify AFL_CC independently from CC.
            "${MAKE:-make}" -C "$test_tmp/project" -n -B V=1 \
                CC=false AFL_CC="${CC:-cc}" TARGET_MACHINE="$target_machine" \
                WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CFLAGS='-Wcast-align -Werror' \
                "build/fuzz/$object.o" >"$test_tmp/flags.log"
            if grep -F -- '-Wno-cast-align' "$test_tmp/flags.log" >/dev/null; then
                test "$object" != vv_decoder
            else
                test "$object" = vv_decoder
            fi
            "${MAKE:-make}" -C "$test_tmp/project" -n -B V=1 \
                CC="${CC:-cc}" AFL_CC=false TARGET_MACHINE="$target_machine" \
                WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CFLAGS='-Wcast-align -Werror' \
                "build/fuzz/$object.o" >"$test_tmp/flags.log"
            if grep -F -- '-Wno-cast-align' "$test_tmp/flags.log" >/dev/null; then
                printf 'FAIL: fuzz flags followed CC instead of AFL_CC for %s\n' "$object" >&2
                exit 1
            fi
        done
        printf 'PASS: fuzz compiler discovery keeps alignment exceptions local\n'
        ;;
esac
"${MAKE:-make}" -C "$test_tmp/project" -j1 V=1 \
    CC="${CC:-cc}" AFL_CC="${CC:-cc}" \
    CFLAGS="$test_cflags" \
    WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
    ASAN_CFLAGS='-O1 -g -fsanitize=undefined -fno-sanitize-recover=all' \
    ASAN_LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=all' "$@"

# The >=16-byte bad header reaches vv_decompress; empty input checks the
# harness's short-input path. Any execution/sanitizer error propagates.
printf 'invalid-vv-header' | "$test_tmp/project/fuzz_vv_decompress"
"$test_tmp/project/fuzz_vv_decompress" </dev/null
"$test_tmp/project/fuzz_decompress" </dev/null
for test_harness in fuzz_vv_decompress fuzz_decompress; do
    if "$test_tmp/project/$test_harness" 0<&- >"$test_tmp/read-error.log" 2>&1; then
        printf 'FAIL: %s accepted an input read failure\n' "$test_harness" >&2
        exit 1
    fi
done
printf 'PASS: actual fuzz-build links both harnesses; UBSan short/bad-header smoke\n'

case $(uname -s) in
    Linux*) ;;
    *) echo 'SKIP: GNU linker fault-injection regressions require Linux'; exit 0 ;;
esac
# This wrapper forwards real operations and decoders after controlled faults.
# The expected decoded length comes from the literal RAW frame below.
# Check the linker-visible wrapper declarations even without strict CFLAGS.
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g} -D_DEFAULT_SOURCE \
    -Wmissing-prototypes -Wstrict-prototypes -Werror \
    -I"$test_root/include" -I"$test_root/src" \
    -fsanitize=undefined -fno-sanitize-recover=all -fno-lto -c \
    "$test_root/tests/test_fuzz_io.c" -o "$test_tmp/io.o"
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g} -D_DEFAULT_SOURCE \
    -Wmissing-prototypes -Wstrict-prototypes -Werror \
    -I"$test_root/include" -I"$test_root/src" -DFUZZ_TEST_ARCHIVE=1 \
    -fsanitize=undefined -fno-sanitize-recover=all -fno-lto -c \
    "$test_root/tests/test_fuzz_io.c" -o "$test_tmp/io-archive.o"
# Separate non-LTO objects keep linker --wrap calls after the LTO build.
rm -f -- "$test_tmp/project/fuzz_decompress" "$test_tmp/project/fuzz_vv_decompress"
"${MAKE:-make}" -C "$test_tmp/project" -j1 V=1 \
    CC="${CC:-cc}" AFL_CC="${CC:-cc}" \
    CFLAGS="$test_cflags" \
    WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
    FUZZ_BUILD_DIR=build/fuzz-wrap \
    ASAN_CFLAGS='-O1 -g -fsanitize=undefined -fno-sanitize-recover=all -fno-lto' \
    ASAN_LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=all -fno-lto' \
    LDLIBS="${LDLIBS:-} $test_tmp/io.o -Wl,--wrap=read,--wrap=write,--wrap=mkstemp,--wrap=mkdtemp,--wrap=vv_decompress" \
    fuzz_vv_decompress
"${MAKE:-make}" -C "$test_tmp/project" -j1 V=1 \
    CC="${CC:-cc}" AFL_CC="${CC:-cc}" \
    CFLAGS="$test_cflags" \
    WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
    FUZZ_BUILD_DIR=build/fuzz-wrap \
    ASAN_CFLAGS='-O1 -g -fsanitize=undefined -fno-sanitize-recover=all -fno-lto' \
    ASAN_LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=all -fno-lto' \
    LDLIBS="${LDLIBS:-} $test_tmp/io-archive.o -Wl,--wrap=read,--wrap=write,--wrap=mkstemp,--wrap=mkdtemp,--wrap=vv_decompress,--wrap=zupt_extract_archive,--wrap=zupt_test_archive,--wrap=zupt_list_archive" \
    fuzz_decompress
printf '\000\001VV\001\000\000\020\014\000\000\000\000\000\000\000\144\000\000\000fuzz payload' >"$test_tmp/raw.vv"
mkdir -p "$test_tmp/input/nested"
printf 'archive fuzz payload\n' >"$test_tmp/input/nested/payload.txt"
"$test_cli" c -s "$test_tmp/seed.zupt" "$test_tmp/input" >/dev/null
"$test_cli" t "$test_tmp/seed.zupt" >/dev/null

for test_mode in normal read-eintr read-short; do
    ZUPT_FUZZ_IO_MODE=$test_mode "$test_tmp/project/fuzz_vv_decompress" \
        <"$test_tmp/raw.vv" >"$test_tmp/vv-$test_mode.log" 2>&1
    grep -F 'FUZZ-TARGET: vv input=32 result=12' "$test_tmp/vv-$test_mode.log" >/dev/null
done
printf 'PASS: exact valid RAW frame reaches the real decoder after short/interrupted reads\n'

for test_mode in directory-error write-error; do
    if ZUPT_FUZZ_IO_MODE=$test_mode "$test_tmp/project/fuzz_decompress" \
        <"$test_tmp/seed.zupt" >"$test_tmp/$test_mode.log" 2>&1; then
        printf 'FAIL: archive harness accepted %s\n' "$test_mode" >&2
        exit 1
    fi
    if grep -F 'FUZZ-TARGET:' "$test_tmp/$test_mode.log" >/dev/null; then
        printf 'FAIL: target invoked after %s\n' "$test_mode" >&2
        exit 1
    fi
    sed -n 's/^FUZZ-TEMP: //p' "$test_tmp/$test_mode.log" |
        while IFS= read -r test_path; do
            if test -e "$test_path" || test -L "$test_path"; then
                printf 'FAIL: archive harness retained a temporary path after %s\n' "$test_mode" >&2
                exit 1
            fi
        done
done
mkdir "$test_tmp/sentinel"
printf 'preserve this file\n' >"$test_tmp/sentinel/keep"
for test_mode in normal read-eintr read-short write-eintr write-short normal; do
    ZUPT_FUZZ_IO_MODE=$test_mode ZUPT_FUZZ_SENTINEL="$test_tmp/sentinel" \
        "$test_tmp/project/fuzz_decompress" \
        <"$test_tmp/seed.zupt" >"$test_tmp/archive-$test_mode.log" 2>&1
    for test_operation in extract test list; do
        grep -F "FUZZ-TARGET: $test_operation result=0" "$test_tmp/archive-$test_mode.log" >/dev/null
    done
    sed -n 's/^FUZZ-TEMP: //p' "$test_tmp/archive-$test_mode.log" |
        while IFS= read -r test_path; do
            if test -e "$test_path" || test -L "$test_path"; then
                printf 'FAIL: archive harness retained its temporary path\n' >&2
                exit 1
            fi
        done
    test -f "$test_tmp/sentinel/keep"
    test "$(cat "$test_tmp/sentinel/keep")" = 'preserve this file'
done
printf 'PASS: real archive extraction/test/list, short/interrupted writes, setup failure and complete cleanup\n'
