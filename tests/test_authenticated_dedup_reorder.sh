#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
bin=${1:-$repo_root/zupt}
case "$bin" in
    /*) ;;
    *) bin="$(pwd -P)/${bin#./}" ;;
esac
surgery="$repo_root/tests/archive_surgery.py"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-dedup-auth.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

expect_rejected() {
    archive=$1
    description=$2
    stderr="$tmp/rejected.stderr"
    if "$bin" test --pass-file "$tmp/password" "$archive" \
            >/dev/null 2>"$stderr"; then
        fail "$description was accepted"
    fi
    grep -F 'Authentication failed' "$stderr" >/dev/null ||
        fail "$description was rejected for a reason other than authentication"
}

test -x "$bin" || fail "$bin is not executable"
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'

printf 'authenticated-dedup-test-password\n' > "$tmp/password"
chmod 600 "$tmp/password"

# Equal-size, distinct blocks exercise DATA frame position binding while the
# archive is in dedup mode.  Whole-frame swaps and replays preserve each
# frame's internal HMAC, so only its logical-position AAD can reject them
# before extraction trusts the data.
dd if=/dev/urandom of="$tmp/data-a" bs=65536 count=1 2>/dev/null
dd if=/dev/urandom of="$tmp/data-b" bs=65536 count=1 2>/dev/null
cp "$tmp/data-a" "$tmp/two-data-blocks.bin"
dd if="$tmp/data-b" of="$tmp/two-data-blocks.bin" bs=65536 seek=1 \
    conv=notrunc 2>/dev/null

"$bin" compress --dedup --store --block 65536 --threads 1 --kdf pbkdf2 \
    --pass-file "$tmp/password" "$tmp/data.zupt" \
    "$tmp/two-data-blocks.bin" >/dev/null 2>&1 ||
    fail 'could not create encrypted dedup DATA fixture'
"$bin" test --pass-file "$tmp/password" "$tmp/data.zupt" \
    >/dev/null 2>&1 || fail 'clean encrypted dedup DATA fixture is invalid'

python3 "$surgery" swap-frames "$tmp/data.zupt" \
    "$tmp/data-swapped.zupt" --kind data --require-encrypted ||
    fail 'could not construct DATA swap mutation'
expect_rejected "$tmp/data-swapped.zupt" 'encrypted dedup DATA swap'

python3 "$surgery" replay-frame "$tmp/data.zupt" \
    "$tmp/data-replayed.zupt" --kind data --require-encrypted ||
    fail 'could not construct DATA replay mutation'
expect_rejected "$tmp/data-replayed.zupt" 'encrypted dedup DATA replay'

# Three duplicate blocks produce one DATA frame followed by at least two REF
# frames with the same logical content and metadata.  Swapping or replaying
# those REF frames does not alter reconstructed bytes, so content hashes
# cannot mask a missing REF-position binding.
dd if=/dev/urandom of="$tmp/repeated-block" bs=65536 count=1 2>/dev/null
cp "$tmp/repeated-block" "$tmp/repeated.bin"
dd if="$tmp/repeated-block" of="$tmp/repeated.bin" bs=65536 seek=1 \
    conv=notrunc 2>/dev/null
dd if="$tmp/repeated-block" of="$tmp/repeated.bin" bs=65536 seek=2 \
    conv=notrunc 2>/dev/null

"$bin" compress --dedup --store --block 65536 --threads 1 --kdf pbkdf2 \
    --pass-file "$tmp/password" "$tmp/ref.zupt" "$tmp/repeated.bin" \
    >/dev/null 2>&1 || fail 'could not create encrypted dedup REF fixture'
"$bin" test --pass-file "$tmp/password" "$tmp/ref.zupt" \
    >/dev/null 2>&1 || fail 'clean encrypted dedup REF fixture is invalid'

python3 "$surgery" swap-frames "$tmp/ref.zupt" \
    "$tmp/ref-swapped.zupt" --kind ref --require-encrypted \
    --same-metadata || fail 'could not construct same-content REF swap'
expect_rejected "$tmp/ref-swapped.zupt" 'encrypted dedup REF swap'

python3 "$surgery" replay-frame "$tmp/ref.zupt" \
    "$tmp/ref-replayed.zupt" --kind ref --require-encrypted \
    --same-metadata || fail 'could not construct same-content REF replay'
expect_rejected "$tmp/ref-replayed.zupt" 'encrypted dedup REF replay'

printf 'authenticated dedup reorder/replay: PASS\n'
