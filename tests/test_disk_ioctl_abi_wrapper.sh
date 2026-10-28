#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu

case $(uname -s) in
    Linux) ;;
    *) echo 'SKIP: disk ioctl ABI wrapper controls are Linux-specific'; exit 0 ;;
esac
test_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-ioctl-wrapper.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT HUP INT TERM
mkdir "$test_tmp/tools"
ABI_REAL_GREP=$(command -v grep)
ABI_REAL_CAT=$(command -v cat)
ABI_CONTROL_RUNNER=$test_tmp/runner
export ABI_REAL_GREP ABI_REAL_CAT ABI_CONTROL_RUNNER

cat > "$test_tmp/compiler" <<'SH'
#!/bin/sh
set -eu
if [ "$1" = --version ]; then
    if [ "$ABI_WRAPPER_MODE" = version_failure ]; then exit 37; fi
    if [ "$ABI_WRAPPER_MODE" = model_compile_failure ]; then
        echo 'clang controlled compiler'
        exit 0
    fi
    echo 'controlled compiler'
    exit 0
fi
cpp=0 cflags=0 ldflags=0 ldlibs=0 assertions=1 output=
while [ "$#" -gt 0 ]; do
    case $1 in
        -fsyntax-only) exit 45 ;;
        -DCPP_FLAG_CONTROL) cpp=1 ;;
        -DC_FLAG_CONTROL) cflags=1 ;;
        -Wl,--build-id=none) ldflags=1 ;;
        -lm) ldlibs=1 ;;
        -DNDEBUG) assertions=0 ;;
        -UNDEBUG) assertions=1 ;;
        -o) shift; output=$1 ;;
    esac
    shift
done
if [ "$cpp$cflags$ldflags$ldlibs$assertions" != 11111 ] || [ -z "$output" ]; then
    echo 'FAIL: wrapper dropped caller flags or disabled assertions' >&2
    exit 91
fi
if [ "$ABI_WRAPPER_MODE" = compile_failure ]; then exit 41; fi
cp "$ABI_CONTROL_RUNNER" "$output"
chmod +x "$output"
SH
cat > "$test_tmp/runner" <<'SH'
#!/bin/sh
set -eu
case $ABI_WRAPPER_MODE in
    runtime_failure) echo 'control runtime failure' >&2; exit 29 ;;
    address) echo 'AddressSanitizer: control diagnostic' >&2 ;;
    leak) echo 'LeakSanitizer: control diagnostic' >&2 ;;
    undefined) echo 'UndefinedBehaviorSanitizer: control diagnostic' >&2 ;;
    runtime_error) echo 'runtime error: control diagnostic' >&2 ;;
    missing_marker) exit 0 ;;
    duplicate_marker)
        echo 'PASS: disk ioctl request ABI, size/capacity and failure guards' ;;
esac
echo 'PASS: disk ioctl request ABI, size/capacity and failure guards'
SH
cat > "$test_tmp/tools/grep" <<'SH'
#!/bin/sh
if [ "$ABI_WRAPPER_MODE" = grep_failure ]; then exit 2; fi
if [ "$1" = -aFxc ]; then
    if [ "$ABI_WRAPPER_MODE" = completion_grep_failure ]; then exit 2; fi
    if [ "$ABI_WRAPPER_MODE" = malformed_marker_count ]; then exit 0; fi
fi
exec "$ABI_REAL_GREP" "$@"
SH
cat > "$test_tmp/tools/cat" <<'SH'
#!/bin/sh
if [ "$ABI_WRAPPER_MODE" = log_read_failure ]; then exit 23; fi
exec "$ABI_REAL_CAT" "$@"
SH
cat > "$test_tmp/tools/clang" <<'SH'
#!/bin/sh
echo 'FAIL: unselected PATH clang was invoked' >&2
exit 77
SH
chmod +x "$test_tmp/compiler" "$test_tmp/tools/grep" "$test_tmp/tools/cat" "$test_tmp/tools/clang"

failures=0
for control in good:0 compile_failure:41 runtime_failure:29 \
    address:1 leak:1 undefined:1 runtime_error:1 \
    missing_marker:1 duplicate_marker:1 grep_failure:2 completion_grep_failure:2 \
    malformed_marker_count:1 log_read_failure:23 model_compile_failure:45 \
    version_failure:37 unselected_clang:0; do
    mode=${control%:*}
    expected=${control#*:}
    if PATH="$test_tmp/tools:$PATH" ABI_WRAPPER_MODE="$mode" \
        CC="$test_tmp/compiler" CPPFLAGS=-DCPP_FLAG_CONTROL \
        CFLAGS='-DC_FLAG_CONTROL -DNDEBUG' LDFLAGS=-Wl,--build-id=none \
        LDLIBS=-lm sh "$test_root/tests/test_disk_ioctl_abi.sh" \
            > "$test_tmp/$mode.log" 2>&1; then
        status=0
    else
        status=$?
    fi
    if [ "$mode" = unselected_clang ] && [ "$status" -eq 0 ]; then
        if grep -aFxq 'SKIP: modeled bionic ioctl overload header needs selected Clang' "$test_tmp/$mode.log"; then :; else
            status=91
        fi
    fi
    if [ "$status" -ne "$expected" ]; then
        cat "$test_tmp/$mode.log" >&2
        printf 'FAIL: ioctl ABI wrapper %s returned %s (expected %s)\n' \
            "$mode" "$status" "$expected" >&2
        failures=$((failures + 1))
    else
        printf 'PASS: ioctl ABI wrapper %s (exit %s)\n' "$mode" "$status"
    fi
done
test "$failures" -eq 0
