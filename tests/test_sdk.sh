#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Test zupt SDK-backed PQ encryption (v2.2+)


cd "$(dirname "$0")/.."
ZUPT_BIN="$(realpath ./zupt)"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

cd "$TMPDIR"
PASS=0; FAIL=0
chk() { if [ $? -eq 0 ]; then echo "  OK:   $1"; PASS=$((PASS+1)); else echo "  FAIL: $1"; FAIL=$((FAIL+1)); fi; }
chk_neg() { if [ $? -ne 0 ]; then echo "  OK:   $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 (should have failed)"; FAIL=$((FAIL+1)); fi; }

# Setup: real keypair
"$ZUPT_BIN" keygen --sdk -o key.priv > /dev/null 2>&1
[ -f key.priv ] && [ -f key.priv.pub ]
chk "SDK keygen produces both files"

# Test data
echo "Hello SDK PQ encryption" > input.txt
dd if=/dev/urandom of=large.bin bs=64K count=4 2>/dev/null

# Roundtrip small file
"$ZUPT_BIN" c --pq-sdk key.priv.pub small.zupt input.txt > /dev/null 2>&1
chk "SDK encrypt small"
mkdir -p extract1 && cd extract1
"$ZUPT_BIN" x --pq-sdk ../key.priv ../small.zupt > /dev/null 2>&1
chk "SDK decrypt small"
diff -q input.txt ../input.txt > /dev/null 2>&1
chk "SDK small roundtrip byte-exact"
cd ..

# Roundtrip large file
"$ZUPT_BIN" c --pq-sdk key.priv.pub large.zupt large.bin > /dev/null 2>&1
chk "SDK encrypt large (256KB)"
mkdir -p extract2 && cd extract2
"$ZUPT_BIN" x --pq-sdk ../key.priv ../large.zupt > /dev/null 2>&1
chk "SDK decrypt large"
diff -q large.bin ../large.bin > /dev/null 2>&1
chk "SDK large roundtrip byte-exact"
cd ..

# Wrong key rejected
"$ZUPT_BIN" keygen --sdk -o other.priv > /dev/null 2>&1
"$ZUPT_BIN" x --pq-sdk other.priv small.zupt > /dev/null 2>&1
chk_neg "SDK wrong key rejected"

# Tamper detected.
# F-02 (Zupt 2.2.4): use a deterministic body-region offset, not
# len-50 which occasionally landed in the unauthenticated index
# region. See docs/FINDINGS-2.x.md F-02 for the full analysis.
cp small.zupt tampered.zupt
python3 -c "
b = bytearray(open('tampered.zupt','rb').read())
b[200] ^= 1
open('tampered.zupt','wb').write(bytes(b))
"
"$ZUPT_BIN" x --pq-sdk key.priv tampered.zupt > /dev/null 2>&1
chk_neg "SDK tampered ciphertext rejected"

# Legacy v1 compat: legacy --pq still works
"$ZUPT_BIN" keygen -o legacy.key > /dev/null 2>&1
"$ZUPT_BIN" c --pq legacy.key legacy.zupt input.txt > /dev/null 2>&1
chk "Legacy --pq still encrypts"
mkdir -p extract3 && cd extract3
"$ZUPT_BIN" x --pq ../legacy.key ../legacy.zupt > /dev/null 2>&1
chk "Legacy --pq still decrypts"
cd ..

echo
echo "  Results: $PASS passed, $FAIL failed ($((PASS+FAIL)) tests)"
[ $FAIL -eq 0 ]
