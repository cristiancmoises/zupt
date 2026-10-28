#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
case $(uname -m) in
    x86_64|i686) sha_flags='-msha -mssse3 -msse4.1' ;;
    *) sha_flags='' ;;
esac
# Flags use the same intentional whitespace splitting as existing C tests.
# SHA-NI alone inherits the existing Makefile's scoped Clang alignment policy.
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} -D_DEFAULT_SOURCE -Iinclude -Isrc \
    ${CFLAGS:--O2} -std=c11 -Wall -Wextra -Werror $sha_flags \
    ${SHANI_CFLAGS:-} -c src/zupt_sha256_shani.c -o "$task_tmp/shani.o"
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} -D_DEFAULT_SOURCE -Iinclude -Isrc \
    ${CFLAGS:--O2} -std=c11 -Wall -Wextra -Werror $sha_flags ${LDFLAGS:-} \
    tests/test_ct_timing_harness.c \
    src/zupt_crypto.c src/zupt_sha256.c src/zupt_aes256.c \
    src/zupt_xxh.c src/zupt_keccak.c src/zupt_x25519.c src/zupt_mlkem.c \
    src/zupt_cpuid.c src/zupt_mlock.c "$task_tmp/shani.o" \
    -lm ${LDLIBS:-} -o "$task_tmp/test"
"$task_tmp/test"

# An explicit shell-only negative fixture: no statistical measurement is
# substituted or claimed. A compiler stub emits exit77, while grep reports an
# operational error for the absence scan. The real wrapper must return error2.
bash -eu <<'GUARD_TEST'
guard_tmp=$(mktemp -d)
trap 'rm -rf "$guard_tmp"' EXIT HUP INT TERM
compiler_stub() {
    local output='' previous=''
    for argument in "$@"; do
        if [ "$previous" = -o ]; then output=$argument; fi
        previous=$argument
    done
    [ -n "$output" ] || return 1
    printf '#!/bin/sh\nexit 77\n' > "$output"
    chmod 700 "$output"
}
grep() {
    if [ "$1" = -qE ]; then return 2; fi
    return 0
}
export -f compiler_stub grep
if CC=compiler_stub bash tests/test_ct_timing.sh > "$guard_tmp/output" 2>&1; then
    guard_rc=0
else
    guard_rc=$?
fi
if [ "$guard_rc" -ne 2 ]; then
    cat "$guard_tmp/output"
    printf 'FAIL: routing scan error must override inconclusive status (got %s)\n' "$guard_rc" >&2
    exit 1
fi
if command grep -q 'no raw 1088-byte inline compare loop' "$guard_tmp/output"; then
    scan_rc=0
else
    scan_rc=$?
fi
case "$scan_rc" in
    0) printf 'FAIL: scan error must not be reported as successful absence\n' >&2; exit 1 ;;
    1) ;;
    *) printf 'ERROR: fixture output scan failed (%s)\n' "$scan_rc" >&2; exit 2 ;;
esac
printf 'Timing-wrapper routing-error fixture: PASS\n'
GUARD_TEST
