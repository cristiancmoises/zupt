#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

bin=${1:-./zupt}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-device-capacity.XXXXXXXX")
loop_device=

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [[ -n $loop_device ]]; then
        losetup -d "$loop_device" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$tmp"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        printf 'SKIP: raw-device capacity ioctl tests are POSIX-only\n'
        exit 0
        ;;
esac

dd if=/dev/zero bs=65536 count=2 2>/dev/null | tr '\000' 'C' > "$tmp/source.img"
"$bin" disk backup -s -b 65536 "$tmp/source.zupt" "$tmp/source.img" \
    >/dev/null 2>&1 || fail 'could not build device-capacity fixture'

# Character devices without a demonstrable media size must be rejected before
# any write. /dev/null provides an unprivileged regression for that policy.
if [[ -w /dev/null ]]; then
    if "$bin" disk restore "$tmp/source.zupt" /dev/null \
            >/dev/null 2>"$tmp/unknown-capacity.err"; then
        fail 'disk restore accepted a character device of unknown capacity'
    fi
    grep -Fq 'cannot determine restore device capacity safely' \
        "$tmp/unknown-capacity.err" ||
        fail 'character-device rejection did not exercise the capacity guard'
    printf 'disk device unknown-capacity guard: PASS\n'
else
    printf 'SKIP: unknown-capacity character-device test cannot write /dev/null\n'
fi

if [[ $(uname -s) != Linux ]]; then
    printf 'SKIP: undersized loop-device test is Linux-specific\n'
    exit 0
fi
if [[ $(id -u) -ne 0 || ! -e /dev/loop-control ]] ||
   ! command -v losetup >/dev/null 2>&1 ||
   ! losetup --find >/dev/null 2>&1; then
    printf 'SKIP: undersized loop-device test needs root and an available loop device\n'
    exit 0
fi

dd if=/dev/zero of="$tmp/small-backing.img" bs=65536 count=1 2>/dev/null
cp "$tmp/small-backing.img" "$tmp/small-backing.expected"
loop_device=$(losetup --find --show "$tmp/small-backing.img") || {
    loop_device=
    printf 'SKIP: could not attach an undersized loop device\n'
    exit 0
}
if "$bin" disk restore "$tmp/source.zupt" "$loop_device" \
        >/dev/null 2>"$tmp/undersized.err"; then
    fail 'disk restore accepted an image larger than the target device'
fi
grep -Fq 'exceeds restore device capacity' "$tmp/undersized.err" ||
    fail 'loop-device rejection did not exercise the size guard'
losetup -d "$loop_device"
loop_device=
cmp "$tmp/small-backing.expected" "$tmp/small-backing.img" ||
    fail 'undersized restore wrote to the device before rejecting it'

printf 'disk device capacity guard: PASS (undersized device unchanged)\n'
