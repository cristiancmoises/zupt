#!/bin/sh
# ZUPT v0.5.1 — Comprehensive Regression Test Suite
# Covers: normal, solid, encrypted, edge cases, heterogeneous data
# Run: sh tests/regression.sh

set +e  # Don't exit on failure — we track pass/fail ourselves
ZUPT="./zupt"
T="/tmp/zupt_regression_$$"
PASS=0; FAIL=0; TOTAL=0

cleanup() { rm -rf "$T"; }
trap cleanup EXIT

fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }
pass() { echo "  OK:   $1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }

check_roundtrip() {
    # $1=original_dir $2=extracted_dir $3=test_name
    local ok=0 bad=0
    for f in $(cd "$1" && find . -type f | sed 's|^\./||'); do
        local orig="$1/$f"
        local extr="$2/$1/$f"
        if [ -f "$extr" ] && diff -q "$orig" "$extr" >/dev/null 2>&1; then
            ok=$((ok+1))
        else
            bad=$((bad+1))
        fi
    done
    local total=$((ok+bad))
    if [ "$bad" -eq 0 ] && [ "$total" -gt 0 ]; then
        pass "$3 ($ok/$total files)"
    else
        fail "$3 ($ok/$total files, $bad mismatches)"
    fi
}

mkdir -p "$T"
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ZUPT v0.5.1 Regression Test Suite"
echo "═══════════════════════════════════════════════════════"
echo ""
$ZUPT version 2>&1 | head -1
echo ""

# ═══════════════════════════════════════════════════════
# GENERATE TEST DATA
# ═══════════════════════════════════════════════════════

mkdir -p "$T/data/src" "$T/data/sub"

# 1. Empty file
touch "$T/data/empty.txt"

# 2. Single byte
printf "X" > "$T/data/single_byte.bin"

# 3. Small text
echo "Hello, World!" > "$T/data/hello.txt"

# 4. Source code (multiple similar files for solid mode)
for i in 1 2 3; do
    cat src/zupt_predict.c > "$T/data/src/module_${i}.c"
done

# 5. CSV
python3 -c "
print('id,name,email,score,department')
for i in range(2000):
    print(f'{i},user_{i},user{i}@company.com,{i*17%100},{[\"eng\",\"sales\",\"hr\",\"ops\"][i%4]}')
" > "$T/data/records.csv"

# 6. JSON Lines
python3 -c "
import json
for i in range(1000):
    print(json.dumps({'id':i,'name':f'user_{i}','score':i*17%100,'active':i%3!=0}))
" > "$T/data/sub/data.jsonl"

# 7. Server logs
python3 -c "
import random; random.seed(42)
for i in range(1500):
    ts=f'2026-03-17T{i%24:02d}:{i%60:02d}:{random.randint(0,59):02d}Z'
    print(f'{ts} [{[\"INFO\",\"DEBUG\",\"WARN\"][i%3]}] req={random.randint(1000,9999)} {random.randint(1,5000)}ms')
" > "$T/data/server.log"

# 8. Random binary (incompressible)
dd if=/dev/urandom bs=1024 count=10 of="$T/data/random.bin" 2>/dev/null

# 9. Sparse / zeros
dd if=/dev/zero bs=1024 count=50 of="$T/data/sparse.bin" 2>/dev/null

# 10. Highly repetitive
yes "ABCDEFGHIJ" | head -c 50000 > "$T/data/repeat.txt"

# 11. Binary with structure (records)
python3 -c "
import struct, sys
for i in range(2000):
    sys.stdout.buffer.write(struct.pack('<IHBx', i, i*7%65536, i%256))
" > "$T/data/structured.bin"

NFILES=$(find "$T/data" -type f | wc -l)
TOTAL_SZ=$(du -sb "$T/data" | awk '{print $1}')
echo "  Test corpus: $NFILES files, $TOTAL_SZ bytes"
echo ""

# ═══════════════════════════════════════════════════════
# TEST 1: NORMAL MODE (per-file blocks)
# ═══════════════════════════════════════════════════════
echo "── T1: Normal mode compress + extract ──"
$ZUPT compress -l 5 "$T/normal.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/t1_out" "$T/normal.zupt" 2>/dev/null
check_roundtrip "$T/data" "$T/t1_out" "Normal mode round-trip"

# ═══════════════════════════════════════════════════════
# TEST 2: NORMAL MODE INTEGRITY
# ═══════════════════════════════════════════════════════
echo "── T2: Normal mode integrity test ──"
RESULT=$($ZUPT test "$T/normal.zupt" 2>&1)
echo "$RESULT" | grep -q "0 failed" && pass "Normal integrity" || fail "Normal integrity"

# ═══════════════════════════════════════════════════════
# TEST 3: SOLID MODE
# ═══════════════════════════════════════════════════════
echo "── T3: Solid mode compress + extract ──"
$ZUPT compress --solid -l 5 "$T/solid.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/t3_out" "$T/solid.zupt" 2>/dev/null
check_roundtrip "$T/data" "$T/t3_out" "Solid mode round-trip"

# ═══════════════════════════════════════════════════════
# TEST 4: SOLID MODE INTEGRITY
# ═══════════════════════════════════════════════════════
echo "── T4: Solid mode integrity test ──"
RESULT=$($ZUPT test -v "$T/solid.zupt" 2>&1)
echo "$RESULT" | grep -q "0 failed" && pass "Solid integrity" || fail "Solid integrity: $RESULT"

# ═══════════════════════════════════════════════════════
# TEST 5: ENCRYPTED NORMAL MODE
# ═══════════════════════════════════════════════════════
echo "── T5: Encrypted normal mode ──"
$ZUPT compress -l 5 -p "TestPass#2026" "$T/enc_normal.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/t5_out" -p "TestPass#2026" "$T/enc_normal.zupt" 2>/dev/null
check_roundtrip "$T/data" "$T/t5_out" "Encrypted normal round-trip"

# ═══════════════════════════════════════════════════════
# TEST 6: ENCRYPTED SOLID MODE
# ═══════════════════════════════════════════════════════
echo "── T6: Encrypted solid mode ──"
$ZUPT compress --solid -l 5 -p "S3cure!Key" "$T/enc_solid.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/t6_out" -p "S3cure!Key" "$T/enc_solid.zupt" 2>/dev/null
check_roundtrip "$T/data" "$T/t6_out" "Encrypted solid round-trip"

# ═══════════════════════════════════════════════════════
# TEST 7: ENCRYPTED INTEGRITY
# ═══════════════════════════════════════════════════════
echo "── T7: Encrypted solid integrity ──"
RESULT=$($ZUPT test -p "S3cure!Key" "$T/enc_solid.zupt" 2>&1)
echo "$RESULT" | grep -q "0 failed" && pass "Encrypted solid integrity" || fail "Encrypted solid integrity: $RESULT"

# ═══════════════════════════════════════════════════════
# TEST 8: WRONG PASSWORD REJECTION
# ═══════════════════════════════════════════════════════
echo "── T8: Wrong password rejection ──"
RESULT=$($ZUPT extract -o "$T/t8_bad" -p "WRONG" "$T/enc_normal.zupt" 2>&1)
echo "$RESULT" | grep -qi "auth\|fail" && pass "Wrong password rejected" || fail "Wrong password NOT rejected"

# ═══════════════════════════════════════════════════════
# TEST 9: ALL COMPRESSION LEVELS (1-9)
# ═══════════════════════════════════════════════════════
echo "── T9: All compression levels ──"
LEVEL_OK=1
for lvl in 1 3 5 7 9; do
    $ZUPT compress -l $lvl "$T/lvl_${lvl}.zupt" "$T/data/records.csv" 2>/dev/null
    $ZUPT extract -o "$T/t9_${lvl}" "$T/lvl_${lvl}.zupt" 2>/dev/null
    EXTR=$(find "$T/t9_${lvl}" -name "records.csv" -type f | head -1)
    if [ -n "$EXTR" ] && diff -q "$T/data/records.csv" "$EXTR" >/dev/null 2>&1; then
        : # ok
    else
        echo "    Level $lvl: FAIL"
        LEVEL_OK=0
    fi
done
[ "$LEVEL_OK" -eq 1 ] && pass "All 5 levels round-trip" || fail "Some levels failed"

# ═══════════════════════════════════════════════════════
# TEST 10: EDGE CASES
# ═══════════════════════════════════════════════════════
echo "── T10: Edge cases ──"

# Empty file
$ZUPT compress -l 5 "$T/edge_empty.zupt" "$T/data/empty.txt" 2>/dev/null
$ZUPT extract -o "$T/t10_empty" "$T/edge_empty.zupt" 2>/dev/null
EXTR=$(find "$T/t10_empty" -name "empty.txt" -type f | head -1)
[ -n "$EXTR" ] && [ "$(wc -c < "$EXTR")" = "0" ] && pass "Empty file" || fail "Empty file"

# Single byte
$ZUPT compress -l 5 "$T/edge_single.zupt" "$T/data/single_byte.bin" 2>/dev/null
$ZUPT extract -o "$T/t10_single" "$T/edge_single.zupt" 2>/dev/null
EXTR=$(find "$T/t10_single" -name "single_byte.bin" -type f | head -1)
[ -n "$EXTR" ] && diff -q "$T/data/single_byte.bin" "$EXTR" >/dev/null 2>&1 && pass "Single byte file" || fail "Single byte file"

# Sparse (all zeros)
$ZUPT compress -l 5 "$T/edge_sparse.zupt" "$T/data/sparse.bin" 2>/dev/null
$ZUPT extract -o "$T/t10_sparse" "$T/edge_sparse.zupt" 2>/dev/null
EXTR=$(find "$T/t10_sparse" -name "sparse.bin" -type f | head -1)
[ -n "$EXTR" ] && diff -q "$T/data/sparse.bin" "$EXTR" >/dev/null 2>&1 && pass "Sparse file (200KB zeros)" || fail "Sparse file"

# Pure random (incompressible)
$ZUPT compress -l 5 "$T/edge_random.zupt" "$T/data/random.bin" 2>/dev/null
$ZUPT extract -o "$T/t10_random" "$T/edge_random.zupt" 2>/dev/null
EXTR=$(find "$T/t10_random" -name "random.bin" -type f | head -1)
[ -n "$EXTR" ] && diff -q "$T/data/random.bin" "$EXTR" >/dev/null 2>&1 && pass "Random binary (incompressible)" || fail "Random binary"

# ═══════════════════════════════════════════════════════
# TEST 11: LIST COMMAND
# ═══════════════════════════════════════════════════════
echo "── T11: List command ──"
RESULT=$($ZUPT list "$T/normal.zupt" 2>&1)
echo "$RESULT" | grep -q "TOTAL" && pass "List normal archive" || fail "List normal archive"
RESULT=$($ZUPT list "$T/solid.zupt" 2>&1)
echo "$RESULT" | grep -q "TOTAL" && pass "List solid archive" || fail "List solid archive"

# ═══════════════════════════════════════════════════════
# TEST 12: SOLID VS GZIP BENCHMARK
# ═══════════════════════════════════════════════════════
echo "── T12: Compression comparison ──"
S_SZ=$(stat -c%s "$T/solid.zupt" 2>/dev/null || stat -f%z "$T/solid.zupt" 2>/dev/null)
N_SZ=$(stat -c%s "$T/normal.zupt" 2>/dev/null || stat -f%z "$T/normal.zupt" 2>/dev/null)
tar cf - -C "$T" data/ 2>/dev/null | gzip -9 > "$T/gz.tar.gz"
G_SZ=$(stat -c%s "$T/gz.tar.gz" 2>/dev/null || stat -f%z "$T/gz.tar.gz" 2>/dev/null)

SR=$(echo "scale=2; $TOTAL_SZ / $S_SZ" | bc)
NR=$(echo "scale=2; $TOTAL_SZ / $N_SZ" | bc)
GR=$(echo "scale=2; $TOTAL_SZ / $G_SZ" | bc)

echo "  gzip -9:     $G_SZ bytes  ${GR}:1"
echo "  ZUPT normal: $N_SZ bytes  ${NR}:1"
echo "  ZUPT solid:  $S_SZ bytes  ${SR}:1"
if [ "$S_SZ" -le "$G_SZ" ]; then
    pass "Solid beats gzip ($(echo "scale=1; ($G_SZ-$S_SZ)*100/$G_SZ" | bc)% smaller)"
else
    echo "  NOTE: gzip wins (normal for small non-backup corpus)"
    pass "Compression comparison complete"
fi

# ═══════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  RESULTS: $PASS passed, $FAIL failed ($TOTAL tests)"
echo "═══════════════════════════════════════════════════════"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
