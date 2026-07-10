#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Regression: dedup-encrypted archives must NOT reuse the AES-256-CTR nonce
# across blocks.
#
# v4.2.0 fix: the old per-block nonce was base_nonce XOR block_seq, but dedup
# mode hard-codes block_seq==0 for every data block (the sentinel needed so
# cross-file dedup references authenticate consistently). That collapsed every
# dedup block's nonce to a single value, reusing the CTR keystream across
# distinct plaintexts — a many-time-pad. The nonce is now a fresh random 128-bit
# value per block. This test asserts every encrypted DATA block in a
# dedup-encrypted archive carries a distinct stored nonce.
set -u
ZUPT="${ZUPT_BIN:-./zupt}"
echo "Dedup nonce uniqueness (keystream-reuse regression)"

if ! command -v python3 >/dev/null 2>&1; then
    echo "  - skipped: python3 not available"; exit 0
fi

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
# 1 MiB of random data => many distinct 128 KiB blocks (random never dedups).
head -c 1048576 /dev/urandom > "$T/f.bin"
"$ZUPT" compress --dedup -p testpw "$T/a.zupt" "$T/f.bin" >/dev/null 2>&1

python3 - "$T/a.zupt" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
nonces = []; i = 0
def rv(p):
    v = s = 0
    while True:
        b = d[p]; p += 1; v |= (b & 127) << s
        if not (b & 128): break
        s += 7
    return v, p
while True:
    j = d.find(b'\xbb\x01', i)
    if j < 0 or j + 7 > len(d): break
    bt = d[j+2]; flags = d[j+5] | (d[j+6] << 8)
    if bt == 0 and (flags & 1):                    # DATA + ENCRYPTED
        p = j + 7
        _, p = rv(p); _, p = rv(p); p += 8         # skip usz, csz, xxh64
        nonces.append(bytes(d[p:p+16]))            # 16-byte nonce prefix
    i = j + 2
if len(nonces) < 2:
    print("  - inconclusive: only %d encrypted block(s) parsed" % len(nonces)); sys.exit(0)
if len(set(nonces)) == len(nonces):
    print("  ✓ %d encrypted dedup blocks, all %d nonces distinct" % (len(nonces), len(set(nonces))))
    sys.exit(0)
print("  ✗ %d blocks but only %d distinct nonces — CTR KEYSTREAM REUSE" % (len(nonces), len(set(nonces))))
sys.exit(1)
PY
rc=$?
[ $rc -eq 0 ] && echo "  Dedup nonce: 1 passed, 0 failed" || echo "  Dedup nonce: 0 passed, 1 failed"
exit $rc
