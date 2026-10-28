#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu

case $(uname -s) in
    Linux) ;;
    *) echo 'SKIP: disk ioctl ABI regression is Linux-specific'; exit 0 ;;
esac
test_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-ioctl-abi.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT HUP INT TERM
cd "$test_root"

# Compile both declarations on every Linux compiler, even without musl.
# Function sections discard unrelated disk-code dependencies at link time.
for int_request in 1 0; do
    # Honor packager flags, but keep assertions and overflow checks enabled.
    # shellcheck disable=SC2086
    "${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g} \
        -UNDEBUG -D_DEFAULT_SOURCE -DTEST_IOCTL_INT="$int_request" \
        -Iinclude -Isrc -std=c11 -Wall -Wextra -Werror \
        -ffunction-sections -fdata-sections \
        tests/test_disk_ioctl_abi.c ${LDFLAGS:-} -Wl,--gc-sections \
        ${LDLIBS:-} -o "$test_tmp/test-$int_request"
    log=$test_tmp/run-$int_request.log
    if "$test_tmp/test-$int_request" > "$log" 2>&1; then
        status=0
    else
        status=$?
    fi
    cat "$log"
    if [ "$status" -ne 0 ]; then exit "$status"; fi
    if grep -aEq 'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:' "$log"; then
        echo 'FAIL: disk ioctl ABI regression emitted a sanitizer diagnostic' >&2
        exit 1
    else
        scan_status=$?
        if [ "$scan_status" -ne 1 ]; then exit "$scan_status"; fi
    fi
    if completions=$(grep -aFxc 'PASS: disk ioctl request ABI, size/capacity and failure guards' "$log"); then
        if [ "$completions" != 1 ]; then
            echo 'FAIL: disk ioctl ABI regression completion marker is ambiguous' >&2
            exit 1
        fi
    else
        scan_status=$?
        echo 'FAIL: disk ioctl ABI regression completion marker is missing or unreadable' >&2
        exit "$scan_status"
    fi
done

# Clang can expose bionic's unsigned overload alongside its real int ABI.
# Compile the actual, unmocked translation unit against that header shape.
if compiler_banner=$("${CC:-cc}" --version); then
    case $compiler_banner in
        *clang*) model_cc=${CC:-cc} ;;
        *) echo 'SKIP: modeled bionic ioctl overload header needs selected Clang'; exit 0 ;;
    esac
else
    exit "$?"
fi
mkdir -p "$test_tmp/model/sys"
cat > "$test_tmp/model/sys/ioctl.h" <<'HEADER'
/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 * Model of public declarations/Clang attributes, not a bionic implementation.
 * Origin: https://raw.githubusercontent.com/aosp-mirror/platform_bionic/master/libc/include/bits/ioctl.h
 */
int ioctl(int, int, ...);
#if !defined(BIONIC_IOCTL_NO_SIGNEDNESS_OVERLOAD)
int ioctl(int, unsigned int, ...)
    __attribute__((overloadable, enable_if(1, "")));
#endif
HEADER
for caller_optout in '' '-DBIONIC_IOCTL_NO_SIGNEDNESS_OVERLOAD=1'; do
    # shellcheck disable=SC2086
    "$model_cc" ${CPPFLAGS:-} ${CFLAGS:--O2 -g} $caller_optout \
        -D_DEFAULT_SOURCE -isystem "$test_tmp/model" -Iinclude -Isrc \
        -std=c11 -Wall -Wextra -Werror -fsyntax-only src/zupt_disk.c
done
echo 'PASS: modeled bionic ioctl overload header (Clang syntax only; no Android/NDK acceptance)'
