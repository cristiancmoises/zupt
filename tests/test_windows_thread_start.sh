#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu

test_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM
cd "$test_root"

# CC/CPPFLAGS use the same word splitting as the Makefile compiler recipes.
# shellcheck disable=SC2086
${CC:-cc} ${CPPFLAGS:-} -dM -E -x c /dev/null > "$test_tmp/macros"
if grep -q '^#define _WIN32 ' "$test_tmp/macros"; then
    :
else
    probe_status=$?
    if [ "$probe_status" -ne 1 ]; then exit "$probe_status"; fi
    echo 'SKIP: Win32 thread-start ownership requires native Windows'
    exit 0
fi
# shellcheck disable=SC2086
${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    -Wall -Wextra -Werror tests/test_windows_thread_start.c ${LDFLAGS:-} \
    ${LDLIBS:-} -o "$test_tmp/test.exe"
"$test_tmp/test.exe"
