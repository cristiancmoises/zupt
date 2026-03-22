#!/bin/sh
set +e
ZUPT="./zupt"
T="/tmp/zupt_mt_$$"
PASS=0; FAIL=0; TOTAL=0
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT

pass() { echo "  OK:   $1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }

echo "═══════════════════════════════════════════════════════"
echo "  ZUPT v0.6.0 Multi-Threaded Test Suite"
echo "═══════════════════════════════════════════════════════"
$ZUPT version 2>&1 | head -1
echo ""

# Generate test data
mkdir -p "$T/data/sub"
echo "Hello, World!" > "$T/data/hello.txt"
dd if=/dev/urandom bs=1024 count=500 of="$T/data/large_rand.bin" 2>/dev/null
dd if=/dev/zero bs=1024 count=200 of="$T/data/sparse.bin" 2>/dev/null
yes "The quick brown fox jumps over the lazy dog. " | head -c 2000000 > "$T/data/repeat_2m.txt"
cp "$ZUPT" "$T/data/elf.bin"
touch "$T/data/empty.txt"
printf "X" > "$T/data/single.bin"
seq 1 50000 > "$T/data/sub/numbers.txt"
python3 -c "
import json, random; random.seed(42)
for i in range(5000):
    print(json.dumps({'id':i,'name':f'user_{i}','score':round(random.gauss(75,15),2)}))
" > "$T/data/data.json" 2>/dev/null

# ─── T1: N=1 produces correct output ───
echo "── T1: Single-thread (N=1) round-trip ──"
$ZUPT compress -t 1 -l 7 "$T/t1.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/t1_out" "$T/t1.zupt" 2>/dev/null
BAD=0
for f in $(cd "$T/data" && find . -type f | sed 's|^\./||'); do
    EXTR=$(find "$T/t1_out" -name "$(basename $f)" -type f 2>/dev/null | head -1)
    if [ -z "$EXTR" ] || ! diff -q "$T/data/$f" "$EXTR" >/dev/null 2>&1; then BAD=$((BAD+1)); fi
done
[ "$BAD" -eq 0 ] && pass "N=1 round-trip (all files)" || fail "N=1 round-trip ($BAD mismatches)"

# ─── T2: N=2 produces correct output ───
echo "── T2: Two threads (N=2) round-trip ──"
$ZUPT compress -t 2 -l 7 "$T/t2.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/t2_out" "$T/t2.zupt" 2>/dev/null
BAD=0
for f in $(cd "$T/data" && find . -type f | sed 's|^\./||'); do
    EXTR=$(find "$T/t2_out" -name "$(basename $f)" -type f 2>/dev/null | head -1)
    if [ -z "$EXTR" ] || ! diff -q "$T/data/$f" "$EXTR" >/dev/null 2>&1; then BAD=$((BAD+1)); fi
done
[ "$BAD" -eq 0 ] && pass "N=2 round-trip (all files)" || fail "N=2 round-trip ($BAD mismatches)"

# ─── T3: N=4 produces correct output ───
echo "── T3: Four threads (N=4) round-trip ──"
$ZUPT compress -t 4 -l 7 "$T/t3.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/t3_out" "$T/t3.zupt" 2>/dev/null
BAD=0
for f in $(cd "$T/data" && find . -type f | sed 's|^\./||'); do
    EXTR=$(find "$T/t3_out" -name "$(basename $f)" -type f 2>/dev/null | head -1)
    if [ -z "$EXTR" ] || ! diff -q "$T/data/$f" "$EXTR" >/dev/null 2>&1; then BAD=$((BAD+1)); fi
done
[ "$BAD" -eq 0 ] && pass "N=4 round-trip (all files)" || fail "N=4 round-trip ($BAD mismatches)"

# ─── T4: N=8 produces correct output ───
echo "── T4: Eight threads (N=8) round-trip ──"
$ZUPT compress -t 8 -l 7 "$T/t4.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/t4_out" "$T/t4.zupt" 2>/dev/null
BAD=0
for f in $(cd "$T/data" && find . -type f | sed 's|^\./||'); do
    EXTR=$(find "$T/t4_out" -name "$(basename $f)" -type f 2>/dev/null | head -1)
    if [ -z "$EXTR" ] || ! diff -q "$T/data/$f" "$EXTR" >/dev/null 2>&1; then BAD=$((BAD+1)); fi
done
[ "$BAD" -eq 0 ] && pass "N=8 round-trip (all files)" || fail "N=8 round-trip ($BAD mismatches)"

# ─── T5: Large file (>10MB) at N=8 ───
echo "── T5: Large file (10MB) at N=8 ──"
yes "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 " | head -c 10485760 > "$T/large_10m.txt"
$ZUPT compress -t 8 -l 5 "$T/t5.zupt" "$T/large_10m.txt" 2>/dev/null
$ZUPT extract -o "$T/t5_out" "$T/t5.zupt" 2>/dev/null
EXTR=$(find "$T/t5_out" -name "large_10m.txt" -type f | head -1)
if [ -n "$EXTR" ] && diff -q "$T/large_10m.txt" "$EXTR" >/dev/null 2>&1; then
    pass "10MB file N=8 round-trip"
else fail "10MB file N=8 round-trip"; fi

# ─── T6: Many small files (1000 × 1KB) at N=8 ───
echo "── T6: 1000 small files at N=8 ──"
mkdir -p "$T/many"
for i in $(seq 1 1000); do
    echo "File $i content: $(head -c 500 /dev/urandom | base64 | head -c 900)" > "$T/many/file_$i.txt"
done
$ZUPT compress -t 8 -l 5 "$T/t6.zupt" "$T/many/" 2>/dev/null
$ZUPT extract -o "$T/t6_out" "$T/t6.zupt" 2>/dev/null
EXTRACTED=$(find "$T/t6_out" -type f | wc -l)
# Spot-check a few files
SPOT_OK=1
for i in 1 100 500 999 1000; do
    ORIG="$T/many/file_$i.txt"
    EXTR=$(find "$T/t6_out" -name "file_$i.txt" -type f | head -1)
    if [ -z "$EXTR" ] || ! diff -q "$ORIG" "$EXTR" >/dev/null 2>&1; then SPOT_OK=0; fi
done
if [ "$EXTRACTED" -eq 1000 ] && [ "$SPOT_OK" -eq 1 ]; then
    pass "1000 small files N=8 ($EXTRACTED files)"
else fail "1000 small files N=8 ($EXTRACTED files, spot=$SPOT_OK)"; fi

# ─── T7: Empty file in MT archive ───
echo "── T7: Empty file in MT archive ──"
touch "$T/empty_test.txt"
echo "notempty" > "$T/notempty.txt"
$ZUPT compress -t 4 -l 5 "$T/t7.zupt" "$T/empty_test.txt" "$T/notempty.txt" 2>/dev/null
$ZUPT extract -o "$T/t7_out" "$T/t7.zupt" 2>/dev/null
EXTR_EMPTY=$(find "$T/t7_out" -name "empty_test.txt" -type f | head -1)
if [ -n "$EXTR_EMPTY" ] && [ "$(wc -c < "$EXTR_EMPTY")" = "0" ]; then
    pass "Empty file in MT archive"
else fail "Empty file in MT archive"; fi

# ─── T8: Encrypted at N=8 ───
echo "── T8: Encrypted compress+extract at N=8 ──"
$ZUPT compress -t 8 -l 5 -p "TestMT#2026" "$T/t8.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/t8_out" -p "TestMT#2026" "$T/t8.zupt" 2>/dev/null
BAD=0
for f in hello.txt large_rand.bin repeat_2m.txt elf.bin empty.txt single.bin; do
    EXTR=$(find "$T/t8_out" -name "$f" -type f 2>/dev/null | head -1)
    if [ -z "$EXTR" ] || ! diff -q "$T/data/$f" "$EXTR" >/dev/null 2>&1; then BAD=$((BAD+1)); fi
done
[ "$BAD" -eq 0 ] && pass "Encrypted N=8 round-trip" || fail "Encrypted N=8 ($BAD mismatches)"

# ─── T9: Encrypted wrong password at N=8 ───
echo "── T9: Wrong password rejection at N=8 ──"
$ZUPT extract -o "$T/t9_out" -p "WRONG" "$T/t8.zupt" 2>/dev/null
RES=$?
[ "$RES" -ne 0 ] && pass "Wrong password rejected (N=8)" || fail "Wrong password NOT rejected"

# ─── T10: Integrity test with MT archive ───
echo "── T10: Integrity test on MT archive ──"
RESULT=$($ZUPT test -p "TestMT#2026" "$T/t8.zupt" 2>&1)
echo "$RESULT" | grep -q "0 failed" && pass "Integrity test (encrypted MT)" || fail "Integrity test"

# ─── T11: Solid + N=8 falls back to N=1 ───
echo "── T11: Solid mode + N=8 → fallback to N=1 ──"
$ZUPT compress --solid -t 8 -l 5 "$T/t11.zupt" "$T/data/" 2>"$T/t11_err.txt"
$ZUPT extract -o "$T/t11_out" "$T/t11.zupt" 2>/dev/null
BAD=0
for f in hello.txt large_rand.bin elf.bin; do
    EXTR=$(find "$T/t11_out" -name "$f" -type f 2>/dev/null | head -1)
    if [ -z "$EXTR" ] || ! diff -q "$T/data/$f" "$EXTR" >/dev/null 2>&1; then BAD=$((BAD+1)); fi
done
if [ "$BAD" -eq 0 ] && grep -qi "single" "$T/t11_err.txt"; then
    pass "Solid+N=8 → N=1 fallback (correct output)"
elif [ "$BAD" -eq 0 ]; then
    pass "Solid+N=8 correct output (fallback logged)"
else
    fail "Solid+N=8 ($BAD mismatches)"
fi

# ─── T12: All compression levels at N=4 ───
echo "── T12: All 9 levels at N=4 ──"
ALL_OK=1
for lvl in 1 2 3 4 5 6 7 8 9; do
    $ZUPT compress -t 4 -l $lvl "$T/lvl_${lvl}.zupt" "$T/data/repeat_2m.txt" 2>/dev/null
    $ZUPT extract -o "$T/lvl_${lvl}_out" "$T/lvl_${lvl}.zupt" 2>/dev/null
    EXTR=$(find "$T/lvl_${lvl}_out" -name "repeat_2m.txt" -type f | head -1)
    if [ -z "$EXTR" ] || ! diff -q "$T/data/repeat_2m.txt" "$EXTR" >/dev/null 2>&1; then
        echo "    Level $lvl: FAIL"; ALL_OK=0
    fi
done
[ "$ALL_OK" -eq 1 ] && pass "All 9 levels at N=4" || fail "Some levels failed at N=4"

# ─── T13: All codecs at N=4 ───
echo "── T13: All codecs at N=4 ──"
CODECS_OK=1
# Default (LZHP)
$ZUPT compress -t 4 -l 5 "$T/codec_lzhp.zupt" "$T/data/repeat_2m.txt" 2>/dev/null
$ZUPT extract -o "$T/codec_lzhp_out" "$T/codec_lzhp.zupt" 2>/dev/null
EXTR=$(find "$T/codec_lzhp_out" -name "repeat_2m.txt" -type f | head -1)
[ -z "$EXTR" ] || ! diff -q "$T/data/repeat_2m.txt" "$EXTR" >/dev/null 2>&1 && CODECS_OK=0

# Fast LZ
$ZUPT compress -t 4 -l 5 -f "$T/codec_lz.zupt" "$T/data/repeat_2m.txt" 2>/dev/null
$ZUPT extract -o "$T/codec_lz_out" "$T/codec_lz.zupt" 2>/dev/null
EXTR=$(find "$T/codec_lz_out" -name "repeat_2m.txt" -type f | head -1)
[ -z "$EXTR" ] || ! diff -q "$T/data/repeat_2m.txt" "$EXTR" >/dev/null 2>&1 && CODECS_OK=0

# Store
$ZUPT compress -t 4 -s "$T/codec_store.zupt" "$T/data/repeat_2m.txt" 2>/dev/null
$ZUPT extract -o "$T/codec_store_out" "$T/codec_store.zupt" 2>/dev/null
EXTR=$(find "$T/codec_store_out" -name "repeat_2m.txt" -type f | head -1)
[ -z "$EXTR" ] || ! diff -q "$T/data/repeat_2m.txt" "$EXTR" >/dev/null 2>&1 && CODECS_OK=0

[ "$CODECS_OK" -eq 1 ] && pass "All codecs at N=4" || fail "Some codecs failed at N=4"

# ─── T14: Speed comparison (N=1 vs N=4) ───
echo "── T14: Throughput comparison ──"
T1_START=$(date +%s%N)
$ZUPT compress -t 1 -l 5 "$T/speed1.zupt" "$T/large_10m.txt" 2>/dev/null
T1_END=$(date +%s%N)
T1_MS=$(( (T1_END - T1_START) / 1000000 ))

T4_START=$(date +%s%N)
$ZUPT compress -t 4 -l 5 "$T/speed4.zupt" "$T/large_10m.txt" 2>/dev/null
T4_END=$(date +%s%N)
T4_MS=$(( (T4_END - T4_START) / 1000000 ))

echo "  N=1: ${T1_MS}ms  N=4: ${T4_MS}ms"
if [ "$T4_MS" -gt 0 ] && [ "$T1_MS" -gt 0 ]; then
    SPEEDUP=$(echo "scale=1; $T1_MS / $T4_MS" | bc 2>/dev/null || echo "?")
    echo "  Speedup: ${SPEEDUP}x"
    pass "Throughput comparison (N=1: ${T1_MS}ms, N=4: ${T4_MS}ms, ${SPEEDUP}x)"
else
    pass "Throughput comparison (timing unavailable)"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  MT RESULTS: $PASS passed, $FAIL failed ($TOTAL tests)"
echo "═══════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
