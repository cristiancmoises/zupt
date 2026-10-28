#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu

test_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM
cd "$test_root"

# Deliberately compile the production translation unit separately:
# inlining the private estimator in a different test context can hide warnings.
# CC/CPPFLAGS/CFLAGS use the same word splitting as make's compiler recipes.
# shellcheck disable=SC2086
${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    ${VV_ANS_CFLAGS:-} -D_DEFAULT_SOURCE -Iinclude -Isrc -Wall -Wextra -Werror \
    -c src/vv_ans.c -o "$test_tmp/vv_ans.o"
# The estimator stays static; this test includes its actual implementation.
# Only these two contexts inherit the existing vv_ans-local compiler policy.
# shellcheck disable=SC2086
${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    ${VV_ANS_CFLAGS:-} -D_DEFAULT_SOURCE -Iinclude -Isrc -Wall -Wextra -Werror \
    -c tests/test_huffman_estimator.c -o "$test_tmp/test.o"
# shellcheck disable=SC2086
${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} \
    -D_DEFAULT_SOURCE -Iinclude -Isrc -Wall -Wextra -Werror \
    -c src/vv_huffman.c -o "$test_tmp/vv_huffman.o"
# shellcheck disable=SC2086
${CC:-cc} ${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Werror} ${LDFLAGS:-} \
    "$test_tmp/test.o" "$test_tmp/vv_huffman.o" -lm ${LDLIBS:-} -o "$test_tmp/test"
"$test_tmp/test" > "$test_tmp/transcript.bin"
expected=$(sed -n '/^[0-9a-f]\{64\}$/p' tests/fixtures/huffman-estimator.sha256)
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$test_tmp/transcript.bin")
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$test_tmp/transcript.bin")
else
    echo 'FAIL: SHA-256 utility unavailable' >&2
    exit 1
fi
actual=${actual%% *}
if [ "$actual" != "$expected" ]; then
    printf 'FAIL: pre-fix byte parity: expected %s, got %s\n' "$expected" "$actual" >&2
    exit 1
fi
printf 'PASS: pre-fix length and encoded-byte parity (%s)\n' "$actual"
