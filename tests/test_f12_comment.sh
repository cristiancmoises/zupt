#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# F-12 regression test (Zupt 2.4.3).
#
# F-12: implement the reserved `comment_offset` field in zupt_archive_header_t.
# Adds ZUPT_BLOCK_COMMENT (0x05) block type written between data blocks and
# the central index. Comments are plaintext UTF-8 (max 4096 B), encrypted
# along with data blocks when -p/--pq is set. Old readers (v2.4.2 and prior)
# ignore the comment_offset field and skip the block; new readers extract
# and display the comment after the file extraction summary.
#
# Assertions:
#   1. Roundtrip the comment text in plaintext mode.
#   2. Roundtrip the comment text in Argon2id-password mode.
#   3. Roundtrip the comment text in PBKDF2-password mode.
#   4. Roundtrip the comment text in PQ-SDK mode.
#   5. `zupt info` reports the presence of a comment without revealing it
#      (encrypted archives shouldn't leak comment plaintext via info).
#   6. Tampering the comment block payload is rejected (per-block HMAC).
#   7. Tampering hdr.comment_offset is rejected (covered by AIT).
#   8. An archive without a comment shows no Comment: line in info.
#   9. --comment-file path reads the comment from disk.
#  10. Empty comment string is treated as no-comment (header offset stays 0).

set -u

ZUPT="${ZUPT_BIN:-./zupt}"
case "$ZUPT" in
    /*) ;;
    *)  ZUPT="$PWD/$ZUPT" ;;
esac
if [ ! -x "$ZUPT" ]; then
    echo "  ✗ $ZUPT not found — run 'make' first" >&2
    exit 1
fi

PASS=0
FAIL=0
P() { PASS=$((PASS+1)); echo "  ✓ $1"; }
F() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR"

echo "F-12 regression: archive comments"

echo "F-12 payload" > input.txt
COMMENT="archive comment for sprint 2.4.3 test"

# Test 1: plaintext roundtrip
"$ZUPT" c -c "$COMMENT" plain.zupt input.txt >/dev/null 2>&1
mkdir out_p
OUT=$( (cd out_p && "$ZUPT" x ../plain.zupt) 2>&1 )
if echo "$OUT" | grep -qF "$COMMENT"; then
    P "plaintext: comment roundtrips"
else
    F "plaintext: comment not shown on extract"
fi

# Test 2: Argon2id-password roundtrip
"$ZUPT" c -c "$COMMENT" -p secret arg.zupt input.txt >/dev/null 2>&1
mkdir out_a
OUT=$( (cd out_a && "$ZUPT" x -p secret ../arg.zupt) 2>&1 )
if echo "$OUT" | grep -qF "$COMMENT"; then
    P "Argon2id: comment roundtrips"
else
    F "Argon2id: comment not shown"
fi

# Test 3: PBKDF2-password roundtrip
"$ZUPT" c -c "$COMMENT" -p secret --kdf pbkdf2 pb.zupt input.txt >/dev/null 2>&1
mkdir out_pb
OUT=$( (cd out_pb && "$ZUPT" x -p secret ../pb.zupt) 2>&1 )
if echo "$OUT" | grep -qF "$COMMENT"; then
    P "PBKDF2: comment roundtrips"
else
    F "PBKDF2: comment not shown"
fi

# Test 4: PQ-SDK roundtrip
"$ZUPT" keygen --sdk -o k.priv >/dev/null 2>&1
"$ZUPT" c -c "$COMMENT" --pq-sdk k.priv.pub pq.zupt input.txt >/dev/null 2>&1
mkdir out_pq
OUT=$( (cd out_pq && "$ZUPT" x --pq-sdk ../k.priv ../pq.zupt) 2>&1 )
if echo "$OUT" | grep -qF "$COMMENT"; then
    P "PQ-SDK: comment roundtrips"
else
    F "PQ-SDK: comment not shown"
fi

# Test 5: info doesn't leak comment plaintext for encrypted archives
INFO=$("$ZUPT" info arg.zupt 2>&1)
if echo "$INFO" | grep -qF "$COMMENT"; then
    F "info leaks comment plaintext for encrypted archive"
else
    P "info doesn't leak comment plaintext for encrypted archive"
fi
if echo "$INFO" | grep -q "Comment:.*present"; then
    P "info reports comment presence"
else
    F "info doesn't report comment presence"
fi

# Test 6: tampering the comment block payload is rejected
# Find the comment block offset: it's stored in hdr[44..51] (comment_offset).
COMM_OFF=$(python3 -c "
b = open('pq.zupt','rb').read()
print(int.from_bytes(b[44:52],'little'))
")
# Tamper a byte inside the comment block payload (skip the 2-byte magic).
# Pick offset COMM_OFF + 20 which should land inside encrypted payload bytes.
cp pq.zupt tamp_comment.zupt
python3 -c "
b = bytearray(open('tamp_comment.zupt','rb').read())
b[$COMM_OFF + 20] ^= 1
open('tamp_comment.zupt','wb').write(bytes(b))"
mkdir out_tc
ERR=$( (cd out_tc && "$ZUPT" x --pq-sdk ../k.priv ../tamp_comment.zupt) 2>&1 || true )
if [ ! -f out_tc/input.txt ]; then
    P "comment-block tamper rejected (per-block HMAC)"
else
    F "comment-block tamper silently accepted"
fi

# Test 7: tampering hdr.comment_offset is rejected (covered by AIT)
cp pq.zupt tamp_offset.zupt
python3 -c "
b = bytearray(open('tamp_offset.zupt','rb').read())
b[44] ^= 1  # low byte of comment_offset field
open('tamp_offset.zupt','wb').write(bytes(b))"
mkdir out_to
ERR=$( (cd out_to && "$ZUPT" x --pq-sdk ../k.priv ../tamp_offset.zupt) 2>&1 || true )
if [ ! -f out_to/input.txt ]; then
    P "comment_offset tamper rejected (AIT covers header)"
else
    F "comment_offset tamper silently accepted"
fi

# Test 8: archive without comment shows no Comment: line
"$ZUPT" c -p secret nocomment.zupt input.txt >/dev/null 2>&1
INFO2=$("$ZUPT" info nocomment.zupt 2>&1)
if ! echo "$INFO2" | grep -q "Comment:"; then
    P "no-comment archive: info has no Comment: line"
else
    F "no-comment archive: info shows Comment: anyway"
fi

# Test 9: --comment-file reads from disk
echo -n "comment from a file" > cf.txt
"$ZUPT" c --comment-file cf.txt -p secret cf.zupt input.txt >/dev/null 2>&1
mkdir out_cf
OUT=$( (cd out_cf && "$ZUPT" x -p secret ../cf.zupt) 2>&1 )
if echo "$OUT" | grep -qF "comment from a file"; then
    P "--comment-file: comment roundtrips"
else
    F "--comment-file: comment lost: $OUT"
fi

# Test 10: empty -c is treated as no-comment
"$ZUPT" c -c "" empty.zupt input.txt >/dev/null 2>&1
INFO3=$("$ZUPT" info empty.zupt 2>&1)
if ! echo "$INFO3" | grep -q "Comment:"; then
    P "empty -c treated as no-comment"
else
    F "empty -c written as a comment block (should be no-op)"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  F-12 regression: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
