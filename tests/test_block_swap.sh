#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Bug #16 regression — Block-swap attack on encrypted archives.
#
# Pre-fix vulnerability:
#   AES-CTR + HMAC-SHA256 in zupt 2.2.2 covered MAC over (nonce || ciphertext)
#   only. The decryptor read the nonce from the package itself and ignored
#   the block_seq parameter. An attacker who swapped two valid encrypted
#   blocks (header + payload) between positions could produce an archive
#   that decrypts cleanly but extracts files with the wrong content.
#
# Fix:
#   Bind block_seq into MAC as 8-byte LE AAD. Encrypt is now MAC-over
#   (nonce || ciphertext || block_seq_LE). Decrypt tries v2 first, falls
#   back to legacy v1 for old archives. Per-file block_seq is used so
#   extract-side counter matches encrypt-side without needing extra
#   index metadata.
#
# This test:
#   1. Creates an encrypted archive with two distinct files A and B
#   2. Performs the block-swap surgery on the binary
#   3. Verifies extract REJECTS the swapped archive (auth failure)
#   4. Also verifies normal extract still works (regression guard)

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
surgery="$repo_root/tests/archive_surgery.py"
python3 "$repo_root/tests/test_block_swap_fixture.py" || exit 1

ZUPT_BIN=${1:-./zupt}
case $ZUPT_BIN in
    /*) ;;
    *) ZUPT_BIN=$PWD/${ZUPT_BIN#./} ;;
esac
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
cd "$test_root" || exit 1

PASS=0; FAIL=0
chk() {
    if [ $? -eq 0 ]; then echo "  ✓ $1"; PASS=$((PASS+1))
    else echo "  ✗ $1"; FAIL=$((FAIL+1)); fi
}

echo "  [Bug #16 — Block-swap (reorder) attack defense]"

# Two distinct files, small enough that each fits in one block
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' > file_A.txt
printf 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n' > file_B.txt

# Build encrypted archive (small block to ensure 1 block per file)
"$ZUPT_BIN" c -p mypassword -b 64 -t 1 archive.zupt file_A.txt file_B.txt > /dev/null 2>&1

# P1: Normal extract still works (regression guard)
mkdir extract_normal
"$ZUPT_BIN" x archive.zupt -p mypassword -o extract_normal > /dev/null 2>&1
[ -f extract_normal/file_A.txt ] && [ -f extract_normal/file_B.txt ] && \
    diff -q file_A.txt extract_normal/file_A.txt > /dev/null && \
    diff -q file_B.txt extract_normal/file_B.txt > /dev/null
chk "Normal extract still works (regression guard)"

# P2: The block-swap attack must FAIL (no files extracted, or wrong files rejected)
python3 "$surgery" swap-frames archive.zupt archive_swapped.zupt \
    --kind data --require-encrypted
swap_status=$?

if [ $swap_status -eq 0 ]; then
    auth_out=$("$ZUPT_BIN" test archive_swapped.zupt -p mypassword 2>&1)
    auth_rc=$?
    mkdir extract_attack
    out=$("$ZUPT_BIN" x archive_swapped.zupt -p mypassword -o extract_attack 2>&1)
    rc=$?
    installed=$(find extract_attack -mindepth 1 -print -quit)
    installed_status=$?

    # A parser error is not authentication evidence: the valid swapped frames
    # must fail authentication, extraction must fail, and no plaintext may be
    # installed. The test command reports the authentication reason, while
    # extraction reports only its aggregate error count for this fixture.
    if [ "$auth_rc" -ne 0 ] &&
       printf '%s\n' "$auth_out" | grep -Fq 'Authentication failed' &&
       [ "$rc" -ne 0 ] &&
       [ "$installed_status" -eq 0 ] && [ -z "$installed" ]; then
        true
    else
        printf '%s\n' "$auth_out" "$out" >&2
        false
    fi
    chk "Block-swap attack rejected (cross-file reorder)"
else
    false
    chk "Block-swap attack rejected (test archive could not be constructed)"
fi

# P3: Single-block file (boundary case — empty seq_AAD doesn't degenerate)
echo "single block content" > tiny.txt
"$ZUPT_BIN" c -p mypassword tiny.zupt tiny.txt > /dev/null 2>&1
mkdir tiny_out
"$ZUPT_BIN" x tiny.zupt -p mypassword -o tiny_out > /dev/null 2>&1
[ -f tiny_out/tiny.txt ] && diff -q tiny.txt tiny_out/tiny.txt > /dev/null
chk "Single-block file roundtrip (boundary)"

# P4: Multi-block large file (ensures every block has correct AAD seq)
dd if=/dev/urandom of=big.bin bs=1024 count=512 2>/dev/null
"$ZUPT_BIN" c -p mypassword big.zupt big.bin > /dev/null 2>&1
mkdir big_out
"$ZUPT_BIN" x big.zupt -p mypassword -o big_out > /dev/null 2>&1
[ -f big_out/big.bin ] && diff -q big.bin big_out/big.bin > /dev/null
chk "512KB multi-block file roundtrip"

# P5: Multiple files in one archive (each gets per-file seq counter)
echo "first" > a.txt
echo "second" > b.txt
echo "third" > c.txt
"$ZUPT_BIN" c -p mypassword multi.zupt a.txt b.txt c.txt > /dev/null 2>&1
mkdir multi_out
"$ZUPT_BIN" x multi.zupt -p mypassword -o multi_out > /dev/null 2>&1
[ -f multi_out/a.txt ] && [ -f multi_out/b.txt ] && [ -f multi_out/c.txt ] && \
    diff -q a.txt multi_out/a.txt > /dev/null && \
    diff -q b.txt multi_out/b.txt > /dev/null && \
    diff -q c.txt multi_out/c.txt > /dev/null
chk "Multi-file archive roundtrip (per-file seq counters)"

# P6: Wrong password still fails cleanly
mkdir wrong_pw
out=$("$ZUPT_BIN" x archive.zupt -p WRONG_PASSWORD -o wrong_pw 2>&1)
[ ! -f wrong_pw/file_A.txt ] || { printf '%s\n' "$out" >&2; false; }
chk "Wrong password rejected"

echo
echo "  ───────────────────────────────────────"
echo "  Block-swap regression: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ $FAIL -eq 0 ]
