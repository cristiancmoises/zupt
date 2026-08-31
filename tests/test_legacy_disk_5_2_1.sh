#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

bin=${1:-./zupt}
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
fixture="$repo_root/tests/fixtures/v5.2.1-encrypted-dedup-disk.zupt.hex"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-legacy-disk.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    "$repo_root/tests/fixture_hex_decode.c" -o "$tmp/fixture-decode" ||
    fail 'could not build fixture decoder'
"$tmp/fixture-decode" "$fixture" "$tmp/legacy.zupt" ||
    fail 'could not decode v5.2.1 fixture'

{
    dd if=/dev/zero bs=65536 count=1 2>/dev/null | tr '\000' 'A'
    dd if=/dev/zero bs=65536 count=1 2>/dev/null | tr '\000' 'B'
    dd if=/dev/zero bs=65536 count=1 2>/dev/null | tr '\000' 'B'
    dd if=/dev/zero bs=65536 count=1 2>/dev/null | tr '\000' 'C'
} > "$tmp/expected.img"
printf '%s\n' 'vaptvupt-5.2.1-fixture' > "$tmp/password"
chmod 600 "$tmp/password"

"$bin" list --pass-file "$tmp/password" "$tmp/legacy.zupt" >/dev/null 2>&1 ||
    fail 'v5.2.1 encrypted+dedup disk fixture could not be listed'
"$bin" test --pass-file "$tmp/password" "$tmp/legacy.zupt" >/dev/null 2>&1 ||
    fail 'v5.2.1 encrypted+dedup disk fixture failed validation'
mkdir "$tmp/extracted"
"$bin" extract --pass-file "$tmp/password" -o "$tmp/extracted" \
    "$tmp/legacy.zupt" >/dev/null 2>&1 ||
    fail 'v5.2.1 encrypted+dedup disk fixture could not be extracted'
cmp "$tmp/expected.img" "$tmp/extracted/legacy-abbc.img" ||
    fail 'v5.2.1 encrypted+dedup generic extraction mismatch'
"$bin" disk restore --pass-file "$tmp/password" \
    "$tmp/legacy.zupt" "$tmp/restored.img" >/dev/null 2>&1 ||
    fail 'v5.2.1 encrypted+dedup disk fixture could not be restored'
cmp "$tmp/expected.img" "$tmp/restored.img" ||
    fail 'v5.2.1 encrypted+dedup disk restore mismatch'

printf 'v5.2.1 encrypted+dedup disk list/test/extract/restore compatibility: PASS\n'
