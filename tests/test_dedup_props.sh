#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Property-based test for zupt dedup path.
# Generates random file sets with intentional duplicates, verifies that
# (a) compressed output is correct (byte-exact roundtrip) and
# (b) dedup actually saves space when duplicates are present.

REPO_ROOT=$(pwd -P)
ZUPT_BIN=${1:-./zupt}
case $ZUPT_BIN in
    /*) ;;
    *) ZUPT_BIN=$PWD/${ZUPT_BIN#./} ;;
esac
ARCHIVE_SURGERY="$REPO_ROOT/tests/archive_surgery.py"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR" || exit 1

PASS=0; FAIL=0
chk() {
    if [ $? -eq 0 ]; then echo "  ✓ $1"; PASS=$((PASS+1))
    else echo "  ✗ $1"; FAIL=$((FAIL+1)); fi
}

# ─── Property 1: dedup roundtrip is byte-exact ──────────────────────────
# Generate 10 random base files + 5 exact duplicates; compress with --dedup;
# extract; verify every file matches its original.
echo "  [P1. Dedup roundtrip preserves all bytes]"

mkdir input
for i in $(seq 1 10); do
    dd if=/dev/urandom of="input/file_$i.bin" bs=4K \
        count=$((RANDOM % 8 + 1)) 2>/dev/null
done
# 5 exact duplicates (same content as file_1..5)
for i in 1 2 3 4 5; do
    cp "input/file_$i.bin" "input/dup_$i.bin"
done

"$ZUPT_BIN" c --dedup test_dedup.zupt input/*.bin > /dev/null 2>&1
chk "Compress with --dedup succeeds"

mkdir extracted
cd extracted || exit 1
"$ZUPT_BIN" x ../test_dedup.zupt > /dev/null 2>&1
chk "Extract --dedup archive succeeds"

all_match=1
for i in $(seq 1 10); do
    candidate=$(find . -type f -path "*/input/file_$i.bin" -print -quit)
    if [ -z "$candidate" ] ||
            ! cmp "../input/file_$i.bin" "$candidate" >/dev/null 2>&1; then
        all_match=0; break
    fi
done
[ $all_match -eq 1 ]
chk "All 10 base files roundtrip byte-exact"

dup_match=1
for i in 1 2 3 4 5; do
    candidate=$(find . -type f -path "*/input/dup_$i.bin" -print -quit)
    if [ -z "$candidate" ] ||
            ! cmp "../input/dup_$i.bin" "$candidate" >/dev/null 2>&1; then
        dup_match=0
        break
    fi
done
[ $dup_match -eq 1 ]
chk "All 5 duplicate files roundtrip byte-exact"

cd ..

# ─── Property 2: dedup reduces size for duplicate-heavy workloads ───────
echo "  [P2. Dedup compresses better than non-dedup on duplicate-heavy data]"

mkdir dups
for i in $(seq 1 20); do
    cp input/file_1.bin "dups/copy_$i.bin"
done

"$ZUPT_BIN" c        no_dedup.zupt    dups/*.bin > /dev/null 2>&1
"$ZUPT_BIN" c --dedup  with_dedup.zupt  dups/*.bin > /dev/null 2>&1

size_no=$(stat -c%s no_dedup.zupt 2>/dev/null || stat -f%z no_dedup.zupt)
size_yes=$(stat -c%s with_dedup.zupt 2>/dev/null || stat -f%z with_dedup.zupt)

[ "$size_yes" -lt "$size_no" ]
chk "Dedup archive ($size_yes B) smaller than non-dedup ($size_no B)"

ratio=$(awk "BEGIN{printf \"%.0f\", $size_yes * 100 / $size_no}")
[ "$ratio" -lt 50 ]
chk "Dedup achieves >50% reduction (got $ratio% of original)"

# ─── Property 3: dedup roundtrip preserves data on duplicate-only sets ──
echo "  [P3. 100% duplicate file set extracts correctly]"

mkdir extr_dups
cd extr_dups || exit 1
"$ZUPT_BIN" x ../with_dedup.zupt > /dev/null 2>&1
chk "Extract heavy-duplicate archive succeeds"

n_extracted=$(find . -name "copy_*.bin" 2>/dev/null | wc -l)
[ "$n_extracted" -eq 20 ]
chk "All 20 duplicate copies extracted (got $n_extracted)"

all_dup_match=1
while IFS= read -r f; do
    if ! cmp "$f" ../input/file_1.bin >/dev/null 2>&1; then
        all_dup_match=0; break
    fi
done < <(find . -type f -name 'copy_*.bin' -print)
[ $all_dup_match -eq 1 ]
chk "All extracted duplicates byte-exact match the original"

cd ..

# ─── Property 4: dedup + encryption coexist correctly ───────────────────
echo "  [P4. Dedup + password encryption work together]"

"$ZUPT_BIN" c --dedup -p dedup-test-password enc_dedup.zupt dups/*.bin > /dev/null 2>&1
chk "Encrypt + dedup compress succeeds"

"$ZUPT_BIN" t -p dedup-test-password enc_dedup.zupt > /dev/null 2>&1
chk "Encrypt + dedup archive test succeeds"

mkdir extr_enc
cd extr_enc || exit 1
"$ZUPT_BIN" x -p dedup-test-password ../enc_dedup.zupt > /dev/null 2>&1
chk "Encrypt + dedup extract succeeds"

n=$(find . -name "copy_*.bin" 2>/dev/null | wc -l)
[ "$n" -eq 20 ]
chk "All 20 copies recovered after enc+dedup ($n found)"

cd ..

# The offset inside a new encrypted DEDUP_REF is itself authenticated. A
# payload-only mutation must fail before it can redirect extraction.
if python3 "$ARCHIVE_SURGERY" flip-payload enc_dedup.zupt \
        tampered_ref.zupt --kind ref --require-encrypted; then
    if "$ZUPT_BIN" t -p dedup-test-password tampered_ref.zupt \
            > /dev/null 2>&1; then
        false
    else
        true
    fi
else
    false
fi
chk "Encrypted dedup reference offset rejects tampering"

echo
echo "  ───────────────────────────────────────"
echo "  Dedup property results: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ $FAIL -eq 0 ]
