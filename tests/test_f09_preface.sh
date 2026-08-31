#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# F-09 regression test (ZUPT 2.3.1).
#
# F-09 closed the per-block frame preface tamper window by:
#   1. Binding the canonical preface (block_type, codec_id, block_flags,
#      sizes, plaintext-XXH64) into the per-block HMAC via the new v1.6
#      ZUPT_FLAG_AAD_PREFACE policy.
#   2. Adding strict structural validation of the encryption-header
#      block's frame preface in read_enc_header (same pattern as F-07
#      for the index block in v2.2.5).
#
# This test flips every serialized block-preface byte in a small v1.6 PBKDF2
# archive and asserts that each mutation is rejected. With pre-F-09 code this
# would show silent acceptances; post-F-09 it must show zero. A PQ-SDK archive
# receives the historical full-archive byte sweep when system libvuptsdk is
# enabled.
#
# Plaintext archives have no HMAC (XXH64 best-effort only), so per-byte
# coverage is intentionally weaker and a different, separately-tracked
# promise.

set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
ZUPT="${ZUPT_BIN:-$repo_root/zupt}"
case "$ZUPT" in
    /*) ;;
    *)  ZUPT="$PWD/$ZUPT" ;;
esac

if [ ! -x "$ZUPT" ]; then
    echo "  ✗ $ZUPT not found — run 'make' first" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo '  ✗ python3 is required for byte-level archive mutations' >&2
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR" || exit 1

printf 'F-09 regression test payload\n' > input.txt
printf 'source-only-preface-password\n' > password.txt
chmod 600 password.txt

run_sweep() {
    local label=$1
    local archive=$2
    local scope=$3
    shift 3
    local -a auth_options=("$@")
    local -a positions=()
    local size
    local position
    local positions_output
    local tested=0
    local undetected_positions=''
    local undetected_count
    local clean_dir="clean-$label"

    size=$(wc -c < "$archive")
    if [ "$size" -lt 100 ] || [ "$size" -gt 10000 ]; then
        echo "  ✗ $label archive has unexpected size $size" >&2
        return 1
    fi

    mkdir "$clean_dir"
    if ! "$ZUPT" extract "${auth_options[@]}" -o "$clean_dir" "$archive" \
            >/dev/null 2>&1 ||
            ! cmp input.txt "$clean_dir/input.txt" >/dev/null 2>&1; then
        echo "  ✗ clean $label archive does not extract byte-exact" >&2
        return 1
    fi

    if [ "$scope" = preface ]; then
        if ! positions_output=$(python3 \
                "$repo_root/tests/archive_surgery.py" preface-positions \
                "$archive") || [ -z "$positions_output" ]; then
            echo "  ✗ could not locate $label block prefaces" >&2
            return 1
        fi
        while IFS= read -r position; do
            [ -n "$position" ] && positions+=("$position")
        done <<<"$positions_output"
        echo "  [F-09: all block-preface bytes in $size-byte $label archive]"
    elif [ "$scope" = full ]; then
        for ((position = 0; position < size; position++)); do
            positions+=("$position")
        done
        echo "  [F-09: exhaustive byte sweep of $size-byte $label archive]"
    else
        echo "  ✗ internal error: unknown sweep scope $scope" >&2
        return 1
    fi

    for position in "${positions[@]}"; do
        if ! python3 - "$archive" t.zupt "$position" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_bytes()
mutated = bytearray(source)
mutated[int(sys.argv[3])] ^= 0x01
pathlib.Path(sys.argv[2]).write_bytes(mutated)
PY
        then
            echo "  ✗ could not mutate $label archive byte $position" >&2
            return 1
        fi
        tested=$((tested + 1))
        if "$ZUPT" test "${auth_options[@]}" t.zupt >/dev/null 2>&1; then
            undetected_positions="$undetected_positions $position"
        fi
    done

    undetected_count=$(printf '%s\n' "$undetected_positions" | wc -w)
    if [ "$undetected_count" -ne 0 ]; then
        echo "  ✗ $label: $undetected_count silent-accepted positions (must be 0)"
        echo "  positions:$undetected_positions"
        return 1
    fi
    echo "  ✓ $label: $tested tamper positions tested, 0 accepted"
}

FAIL=0

if ! "$ZUPT" compress --store --kdf pbkdf2 --pass-file password.txt \
        pbkdf2.zupt input.txt >/dev/null 2>&1; then
    echo '  ✗ could not create source-only PBKDF2 archive' >&2
    exit 1
fi
if ! run_sweep PBKDF2 pbkdf2.zupt preface --pass-file password.txt; then
    FAIL=$((FAIL + 1))
fi

version=$("$ZUPT" --version 2>&1)
if grep -Fq 'libvuptsdk=enabled' <<<"$version"; then
    if ! "$ZUPT" keygen --sdk -o k.priv >/dev/null 2>&1 ||
            ! "$ZUPT" compress --store --pq-sdk k.priv.pub pq-sdk.zupt \
                input.txt >/dev/null 2>&1; then
        echo '  ✗ could not create PQ-SDK archive' >&2
        FAIL=$((FAIL + 1))
    elif ! run_sweep PQ-SDK pq-sdk.zupt full --pq-sdk k.priv; then
        FAIL=$((FAIL + 1))
    fi
else
    echo '  SKIP: additional PQ-SDK sweep needs WITH_SDK=1 and system libvuptsdk'
fi

echo
echo "  ───────────────────────────────────────"
if [ "$FAIL" -eq 0 ]; then
    echo "  F-09 regression: PASS"
else
    echo "  F-09 regression: FAIL ($FAIL archive variants)"
fi
echo "  ───────────────────────────────────────"
[ "$FAIL" -eq 0 ]
