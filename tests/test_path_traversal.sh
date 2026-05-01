#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Path traversal / Zip Slip regression tests.
#
# Verifies that the v2.2.2 audit fixes for CVE-pattern path traversal
# (Snyk Zip Slip 2018) and symlink-following on extract are working.
#
# Tests construct malicious archives in two ways:
#  (A) compress with a relative path then post-mutate the index (manual fuzz)
#  (B) try to extract into a directory containing a symlink with the same
#      name as an archive entry — should be refused due to O_NOFOLLOW.

ZUPT_BIN="$(realpath ./zupt)"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
cd "$TMPDIR"

PASS=0; FAIL=0
chk() {
    if [ $? -eq 0 ]; then echo "  ✓ $1"; PASS=$((PASS+1))
    else echo "  ✗ $1"; FAIL=$((FAIL+1)); fi
}

# ─── Property 1: archive with ".." entry must not extract above target ──
# Strategy: compress an innocent file, then patch the archive's index to
# replace the path with "../../escaped.txt". Extract into a subdir;
# verify the file appears nowhere outside the subdir.
echo "  [P1. Zip Slip — relative path traversal blocked]"

mkdir input output_safe
echo "secret content" > input/innocent.txt
"$ZUPT_BIN" c slip.zupt input/innocent.txt > /dev/null 2>&1

# Patch the archive: replace "input/innocent.txt" path string with
# "../escape.txt" in the index. We use a python helper because the index
# is varint-prefixed and we need to keep length consistent.
python3 << 'PYEOF'
import sys
data = bytearray(open('slip.zupt','rb').read())
target = b'input/innocent.txt'
replacement = b'../escape.txt'
# Pad replacement to same length so varint length prefix stays valid
pad = b'\x00' * (len(target) - len(replacement))
i = data.find(target)
if i < 0:
    print("ERROR: pattern not in archive")
    sys.exit(1)
# Replace the bytes — note this will fail validation below, which is OK,
# we want to see if extract REJECTS the malformed path.
data[i:i+len(target)] = replacement + pad
open('slip_patched.zupt','wb').write(bytes(data))
PYEOF

# Try to extract — even if the patched archive is corrupt, we want to
# verify that NO file appears at "../escape.txt" relative to output_safe.
cd output_safe
"$ZUPT_BIN" x ../slip_patched.zupt > /dev/null 2>&1
cd ..

# The key invariant: nothing escaped to TMPDIR (parent of output_safe)
[ ! -f "$TMPDIR/escape.txt" ] && [ ! -f escape.txt ]
chk "No escape via patched ../escape.txt path"

# ─── Property 2: archive with absolute path must not write to that path ──
echo "  [P2. Absolute path entries blocked]"

# Construct an archive entry with absolute "/tmp/owned.txt" via patching
echo "innocent" > input2.txt
"$ZUPT_BIN" c abs.zupt input2.txt > /dev/null 2>&1
python3 << 'PYEOF'
data = bytearray(open('abs.zupt','rb').read())
target = b'input2.txt'
# Replace with absolute path of equal length
replacement = b'/tmp/owned'  # 10 chars vs 10 chars
i = data.find(target)
if i >= 0:
    data[i:i+len(target)] = replacement
    open('abs_patched.zupt','wb').write(bytes(data))
PYEOF

mkdir abs_extract
cd abs_extract
"$ZUPT_BIN" x ../abs_patched.zupt > /dev/null 2>&1
cd ..

[ ! -f /tmp/owned ]
chk "Absolute /tmp/owned path rejected"

# ─── Property 3: symlink at output target is not followed ──────────────
# Pre-place a symlink in output dir pointing to a sentinel file.
# Extract an archive with the same entry name; verify the sentinel is
# unchanged (i.e. extract refused to follow the symlink).
echo "  [P3. Symlink at extract target not followed]"

echo "DO_NOT_OVERWRITE" > sentinel.txt
mkdir symlink_extract
ln -s "$(pwd)/sentinel.txt" symlink_extract/innocent.txt

# Build a fresh non-patched archive with "innocent.txt"
mkdir input3 && echo "evil overwrite content" > input3/innocent.txt
"$ZUPT_BIN" c clean.zupt input3/innocent.txt > /dev/null 2>&1
# Mutate path "input3/innocent.txt" -> "innocent.txt" so it lands at the symlink
python3 << 'PYEOF'
data = bytearray(open('clean.zupt','rb').read())
target = b'input3/innocent.txt'
replacement = b'innocent.txt' + (b'\x00' * (len(target) - len(b'innocent.txt')))
i = data.find(target)
if i >= 0:
    data[i:i+len(target)] = replacement
    open('clean_patched.zupt','wb').write(bytes(data))
PYEOF

cd symlink_extract
"$ZUPT_BIN" x ../clean_patched.zupt > /dev/null 2>&1
cd ..

# Sentinel must be unchanged — symlink follow would have overwritten it
content=$(cat sentinel.txt)
[ "$content" = "DO_NOT_OVERWRITE" ]
chk "Sentinel via symlink not overwritten"

# ─── Property 4: legitimate paths still extract correctly ─────────────
echo "  [P4. Legitimate (safe) paths still extract]"

mkdir legit_input
echo "ok content" > legit_input/normal.txt
"$ZUPT_BIN" c legit.zupt legit_input/normal.txt > /dev/null 2>&1

mkdir legit_extract && cd legit_extract
"$ZUPT_BIN" x ../legit.zupt > /dev/null 2>&1
cd ..

[ -f legit_extract/legit_input/normal.txt ] && \
    [ "$(cat legit_extract/legit_input/normal.txt)" = "ok content" ]
chk "Normal extraction still works"

# ─── Property 5: deep path (allowed) but parent dir is created ─────────
echo "  [P5. Multi-component safe paths still work]"

mkdir deep && mkdir deep/sub && mkdir deep/sub/sub2
echo "deep" > deep/sub/sub2/file.txt
"$ZUPT_BIN" c deep.zupt deep/sub/sub2/file.txt > /dev/null 2>&1

mkdir deep_extract && cd deep_extract
"$ZUPT_BIN" x ../deep.zupt > /dev/null 2>&1
cd ..

[ -f deep_extract/deep/sub/sub2/file.txt ]
chk "Deep nested path extracted"

echo
echo "  ───────────────────────────────────────"
echo "  Path-traversal regression: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ $FAIL -eq 0 ]
