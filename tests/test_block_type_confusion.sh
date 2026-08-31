#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

bin=${1:-./zupt}
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
surgery="$repo_root/tests/archive_surgery.py"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-block-type.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'python3 is required'
dd if=/dev/zero bs=65536 count=3 2>/dev/null | tr '\000' 'T' > "$tmp/input.bin"
"$bin" compress -s -b 65536 -t 2 "$tmp/original.zupt" "$tmp/input.bin" \
    >/dev/null 2>&1 || fail 'could not create block-type fixture'
python3 "$surgery" set-frame-type "$tmp/original.zupt" \
    "$tmp/comment-frame.zupt" --kind data --type comment ||
    fail 'could not change DATA frame type'

if "$bin" test "$tmp/comment-frame.zupt" >/dev/null 2>&1; then
    fail 'archive test accepted COMMENT in a DATA range'
fi
for threads in 1 2; do
    mkdir "$tmp/out-$threads"
    if "$bin" extract -t "$threads" -o "$tmp/out-$threads" \
            "$tmp/comment-frame.zupt" >/dev/null 2>&1; then
        fail "${threads}-thread extraction accepted COMMENT in a DATA range"
    fi
    if find "$tmp/out-$threads" -type f -print -quit | grep -q .; then
        fail "${threads}-thread extraction published output after type rejection"
    fi
done

printf 'archive DATA-frame type enforcement: PASS\n'
