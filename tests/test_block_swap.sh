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

ZUPT_BIN=${1:-./zupt}
case $ZUPT_BIN in
    /*) ;;
    *) ZUPT_BIN=$PWD/${ZUPT_BIN#./} ;;
esac
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
cd "$TMPDIR"

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
python3 << 'PYEOF'
import sys, struct
data = bytearray(open('archive.zupt','rb').read())
# Find DATA blocks via block magic 0xbb 0x01 + block_type=DATA(0)
def parse_blocks(data):
    blocks = []
    i = 0
    while i < len(data) - 7:
        if data[i] == 0xbb and data[i+1] == 0x01:
            block_type = data[i+2]
            codec = struct.unpack('<H', bytes(data[i+3:i+5]))[0]
            flags = struct.unpack('<H', bytes(data[i+5:i+7]))[0]
            # parse varint uncomp
            idx = i + 7
            uncomp, shift = 0, 0
            while idx < len(data):
                b = data[idx]
                uncomp |= (b & 0x7F) << shift
                idx += 1
                if not (b & 0x80): break
                shift += 7
            comp, shift = 0, 0
            while idx < len(data):
                b = data[idx]
                comp |= (b & 0x7F) << shift
                idx += 1
                if not (b & 0x80): break
                shift += 7
            payload_start = idx + 8  # skip 8-byte checksum
            block_end = payload_start + comp
            blocks.append({
                'type': block_type, 'flags': flags,
                'start': i, 'end': block_end, 'comp': comp,
            })
            i = block_end
        else:
            i += 1
    return blocks

blocks = parse_blocks(data)
data_blocks = [b for b in blocks if b['type'] == 0 and b['flags'] & 0x01]
if len(data_blocks) < 2:
    print(f"Found only {len(data_blocks)} encrypted DATA blocks; can't swap", file=sys.stderr)
    sys.exit(2)

# Swap the first two DATA blocks
B0 = bytes(data[data_blocks[0]['start']:data_blocks[0]['end']])
B1 = bytes(data[data_blocks[1]['start']:data_blocks[1]['end']])
swapped = bytearray(data)
# Swap (assume same size)
if len(B0) != len(B1):
    print(f"different block sizes {len(B0)} vs {len(B1)}; can't swap directly", file=sys.stderr)
    sys.exit(2)
swapped[data_blocks[0]['start']:data_blocks[0]['end']] = B1
swapped[data_blocks[1]['start']:data_blocks[1]['end']] = B0
open('archive_swapped.zupt','wb').write(bytes(swapped))
print(f"swap done", file=sys.stderr)
PYEOF
swap_status=$?

if [ $swap_status -eq 0 ]; then
    mkdir extract_attack
    out=$("$ZUPT_BIN" x archive_swapped.zupt -p mypassword -o extract_attack 2>&1)
    rc=$?

    # Attack defense check: at least one of these must hold
    #   - rc != 0 (extract returned error)
    #   - no files extracted
    #   - extracted files have wrong content (we reject this — would mean the
    #     bug is still present)
    a_swapped=0; b_swapped=0
    [ -f extract_attack/file_A.txt ] && cmp -s file_B.txt extract_attack/file_A.txt && a_swapped=1
    [ -f extract_attack/file_B.txt ] && cmp -s file_A.txt extract_attack/file_B.txt && b_swapped=1

    if [ "$a_swapped" = "1" ] && [ "$b_swapped" = "1" ]; then
        # BAD: attack succeeded — file_A has B's content and vice versa
        false
    else
        # GOOD: attack rejected (either error, no files, or files unchanged)
        true
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
[ ! -f wrong_pw/file_A.txt ]
chk "Wrong password rejected"

echo
echo "  ───────────────────────────────────────"
echo "  Block-swap regression: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ $FAIL -eq 0 ]
