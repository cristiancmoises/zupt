#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu
case $(uname -s) in
    Linux) ;;
    *) echo 'SKIP: partial worker injection requires Linux dynamic ELF'; exit 0 ;;
esac
test_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM
cd "$test_root"
test_binary=${1:-./zupt}
test_binary=$(CDPATH='' cd -- "$(dirname -- "$test_binary")" && pwd)/$(basename -- "$test_binary")
test -x "$test_binary"
command -v timeout >/dev/null
if command -v readelf >/dev/null 2>&1; then
    readelf -l "$test_binary" > "$test_tmp/elf-program-headers"
    if grep -q INTERP "$test_tmp/elf-program-headers"; then
        :
    else
        probe_status=$?
        if [ "$probe_status" -ne 1 ]; then exit "$probe_status"; fi
        echo 'SKIP: partial worker injection requires a dynamically linked ELF'
        exit 0
    fi
else
    echo 'SKIP: partial worker injection needs readelf to verify dynamic ELF'
    exit 0
fi
run_checked() {
    test_log=$1
    shift
    "$@" > "$test_log" 2>&1 || {
        test_status=$?
        sed -n '1,40p' "$test_log" >&2
        printf 'FAIL: worker-start regression command exited %s\n' "$test_status" >&2
        return "$test_status"
    }
}
# Keep both driver and linker in shared mode after distro PIE flags.
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    -fPIC tests/test_partial_worker_start.c ${LDFLAGS:-} \
    -pthread -ldl ${LDLIBS:-} -shared -Wl,-shared -o "$test_tmp/fail-create.so"
python3 - "$test_tmp/input.bin" <<'PY'
import pathlib
import sys
pathlib.Path(sys.argv[1]).write_bytes(bytes(range(256)) * 1536)
PY
"$test_binary" compress -t 1 -b 65536 "$test_tmp/serial.zupt" "$test_tmp/input.bin" \
    > "$test_tmp/serial.log" 2>&1

for started in 0 1 2; do
    archive=$test_tmp/failure-$started.zupt
    run_checked "$test_tmp/compress-$started.log" timeout --kill-after=2s 10s env LD_PRELOAD="$test_tmp/fail-create.so" \
        ZUPT_TEST_THREAD_FAIL_AFTER=$started "$test_binary" compress -t 4 -b 65536 \
        "$archive" "$test_tmp/input.bin"
    grep -F "TEST: deny worker startup after $started successful attempts" \
        "$test_tmp/compress-$started.log" >/dev/null
    if grep -F 'TEST: unexpected real worker startup failure' "$test_tmp/compress-$started.log" >/dev/null; then
        echo 'FAIL: test resource limit prevented the selected worker count' >&2
        exit 1
    fi
    run_checked "$test_tmp/test-$started.log" "$test_binary" test "$archive"
    mkdir "$test_tmp/out-$started"
    run_checked "$test_tmp/extract-$started.log" timeout --kill-after=2s 10s env LD_PRELOAD="$test_tmp/fail-create.so" \
        ZUPT_TEST_THREAD_FAIL_AFTER=$started "$test_binary" extract -t 4 \
        -o "$test_tmp/out-$started" "$test_tmp/serial.zupt"
    grep -F "TEST: deny worker startup after $started successful attempts" \
        "$test_tmp/extract-$started.log" >/dev/null
    if grep -F 'TEST: unexpected real worker startup failure' "$test_tmp/extract-$started.log" >/dev/null; then
        echo 'FAIL: test resource limit prevented the selected worker count' >&2
        exit 1
    fi
    output=$(find "$test_tmp/out-$started" -type f -name input.bin)
    test -n "$output"
    cmp "$test_tmp/input.bin" "$output"
    printf 'PASS: compression/decompression fallback after %s workers; exact payload\n' "$started"
done
