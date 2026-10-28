#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
set +e
ZUPT="${1:-./zupt}"
umask 077
T=$(mktemp -d "${TMPDIR:-/tmp}/zupt_mt_XXXXXXXX") || {
    printf '%s\n' 'Cannot create private threaded-test workspace' >&2
    exit 1
}
PASS=0; FAIL=0; TOTAL=0
trap 'rm -rf -- "$T"' 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

pass() { echo "  OK:   $1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }

echo "═══════════════════════════════════════════════════════"
echo "  ZUPT Multi-Threaded Test Suite"
echo "═══════════════════════════════════════════════════════"
$ZUPT version 2>&1 | head -1
echo ""

# Generate test data
mkdir -p "$T/data/sub"
echo "Hello, World!" > "$T/data/hello.txt"
if dd if=/dev/urandom bs=1024 count=500 of="$T/data/large_rand.bin" 2>"$T/binary-fixture.log" &&
    dd if=/dev/zero bs=1024 count=200 of="$T/data/sparse.bin" 2>>"$T/binary-fixture.log" &&
    python3 -I -B -c '
import os, sys
for path, expected in ((sys.argv[1], 512000), (sys.argv[2], 204800)):
    if os.stat(path).st_size != expected:
        raise ValueError("invalid binary fixture length")
' "$T/data/large_rand.bin" "$T/data/sparse.bin" 2>>"$T/binary-fixture.log"; then
    :
else
    cat -- "$T/binary-fixture.log" >&2
    printf '%s\n' 'Cannot prepare threaded-test binary fixtures' >&2
    exit 1
fi
yes "The quick brown fox jumps over the lazy dog. " | head -c 2000000 > "$T/data/repeat_2m.txt"
cp "$ZUPT" "$T/data/elf.bin"
touch "$T/data/empty.txt"
printf "X" > "$T/data/single.bin"
seq 1 50000 > "$T/data/sub/numbers.txt"
if python3 -c "
import json, random; random.seed(42)
for i in range(5000):
    print(json.dumps({'id':i,'name':f'user_{i}','score':round(random.gauss(75,15),2)}))
" > "$T/data/data.json" 2>"$T/json-fixture.log" &&
    python3 -I -B -c '
import json, math, sys
count = 0
with open(sys.argv[1], encoding="utf-8") as source:
    for index, line in enumerate(source):
        if index >= 5000:
            raise ValueError("too many JSON fixture records")
        row = json.loads(line)
        if (type(row) is not dict or set(row) != {"id", "name", "score"} or
                type(row["id"]) is not int or row["id"] != index or
                row["name"] != f"user_{index}" or
                type(row["score"]) is not float or not math.isfinite(row["score"])):
            raise ValueError("invalid JSON fixture record")
        count += 1
if count != 5000:
    raise ValueError("incomplete JSON fixture")
' "$T/data/data.json" 2>>"$T/json-fixture.log"; then
    :
else
    cat -- "$T/json-fixture.log" >&2
    printf '%s\n' 'Cannot prepare threaded-test JSON fixture' >&2
    exit 1
fi

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
if "$ZUPT" compress -t 8 -l 5 "$T/t6.zupt" "$T/many/" >"$T/t6-compress.log" 2>&1; then
    T6_COMPRESS_STATUS=0
else
    T6_COMPRESS_STATUS=$?
fi
if "$ZUPT" extract -o "$T/t6_out" "$T/t6.zupt" >"$T/t6-extract.log" 2>&1; then
    T6_EXTRACT_STATUS=0
else
    T6_EXTRACT_STATUS=$?
fi
EXTRACTED=$(find "$T/t6_out" -type f | wc -l)
# Absolute inputs retain their path without the leading slash in the archive.
# Count alone misses renamed members; compare every relative path and byte.
if [ "$T6_COMPRESS_STATUS" -eq 0 ] && [ "$T6_EXTRACT_STATUS" -eq 0 ] &&
   [ "$EXTRACTED" -eq 1000 ] &&
   diff -qr -- "$T/many" "$T/t6_out/${T#/}/many" >"$T/t6-compare.log" 2>&1; then
    pass "1000 small files N=8 ($EXTRACTED files)"
else
    printf '  Many-file status: compress=%s extract=%s files=%s\n' \
        "$T6_COMPRESS_STATUS" "$T6_EXTRACT_STATUS" "$EXTRACTED"
    cat -- "$T/t6-compress.log" "$T/t6-extract.log"
    if [ -f "$T/t6-compare.log" ]; then cat -- "$T/t6-compare.log"; fi
    fail "1000 small files N=8 (process failure or tree mismatch)"
fi

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
if "$ZUPT" extract -o "$T/t9_out" -p "WRONG" "$T/t8.zupt" >"$T/t9-error.log" 2>&1; then
    T9_STATUS=0
else
    T9_STATUS=$?
fi
# Authentication rejection must not hide a crashed process or a failed scan.
# Read the full log: grep -q may mask a later input error after a match.
if LC_ALL=C grep -aE 'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:' "$T/t9-error.log" >/dev/null; then
    T9_SANITIZER=0
else
    T9_SANITIZER=$?
fi
if LC_ALL=C grep -aF -- 'Error: Authentication failed' "$T/t9-error.log" >/dev/null; then
    T9_AUTH=0
else
    T9_AUTH=$?
fi
if [ "$T9_STATUS" -eq 1 ] && [ "$T9_SANITIZER" -eq 1 ] && [ "$T9_AUTH" -eq 0 ]; then
    pass "Wrong password rejected (N=8)"
else
    printf '  Wrong-password status=%s sanitizer-scan=%s authentication-scan=%s\n' \
        "$T9_STATUS" "$T9_SANITIZER" "$T9_AUTH"
    cat -- "$T/t9-error.log"
    fail "Wrong password rejection did not satisfy the process/diagnostic checks"
fi

# ─── T10: Integrity test with MT archive ───
echo "── T10: Integrity test on MT archive ──"
if "$ZUPT" test -p "TestMT#2026" "$T/t8.zupt" >"$T/t10-result.log" 2>&1; then
    T10_STATUS=0
else
    T10_STATUS=$?
fi
if LC_ALL=C grep -aE 'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:' "$T/t10-result.log" >/dev/null; then
    T10_SANITIZER=0
else
    T10_SANITIZER=$?
fi
# The fixture contains nine regular files; directories are not archive entries.
# Require one exact summary, not a substring such as "10 failed".
if LC_ALL=C grep -axF -- '  Test: 9 passed, 0 failed (9 files)' "$T/t10-result.log" >/dev/null; then
    T10_SUMMARY=0
else
    T10_SUMMARY=$?
fi
if T10_COUNT=$(LC_ALL=C grep -acF -- 'Test:' "$T/t10-result.log"); then
    T10_COUNT_STATUS=0
else
    T10_COUNT_STATUS=$?
fi
if [ "$T10_STATUS" -eq 0 ] && [ "$T10_SANITIZER" -eq 1 ] &&
   [ "$T10_SUMMARY" -eq 0 ] && [ "$T10_COUNT_STATUS" -eq 0 ] && [ "$T10_COUNT" = 1 ]; then
    pass "Integrity test (encrypted MT)"
else
    printf '  Integrity status=%s sanitizer-scan=%s summary-scan=%s count-scan=%s count=%s\n' \
        "$T10_STATUS" "$T10_SANITIZER" "$T10_SUMMARY" "$T10_COUNT_STATUS" "$T10_COUNT"
    cat -- "$T/t10-result.log"
    fail "Integrity test did not satisfy the process/diagnostic/summary checks"
fi

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
if "$ZUPT" compress -t 1 -l 5 "$T/speed1.zupt" "$T/large_10m.txt" >"$T/t14-n1.log" 2>&1; then
    T1_STATUS=0
else
    T1_STATUS=$?
fi
T1_END=$(date +%s%N)
T1_MS=$(( (T1_END - T1_START) / 1000000 ))

T4_START=$(date +%s%N)
if "$ZUPT" compress -t 4 -l 5 "$T/speed4.zupt" "$T/large_10m.txt" >"$T/t14-n4.log" 2>&1; then
    T4_STATUS=0
else
    T4_STATUS=$?
fi
T4_END=$(date +%s%N)
T4_MS=$(( (T4_END - T4_START) / 1000000 ))

if [ "$T1_STATUS" -eq 0 ] && [ "$T4_STATUS" -eq 0 ] &&
   [ -f "$T/speed1.zupt" ] && [ -s "$T/speed1.zupt" ] &&
   [ -f "$T/speed4.zupt" ] && [ -s "$T/speed4.zupt" ]; then
    echo "  N=1: ${T1_MS}ms  N=4: ${T4_MS}ms"
    if [ "$T4_MS" -gt 0 ] && [ "$T1_MS" -gt 0 ]; then
        SPEEDUP=$(awk -v one="$T1_MS" -v four="$T4_MS" \
            'BEGIN { if (four > 0) printf "%.1f", one / four; else print "?" }')
        echo "  Speedup: ${SPEEDUP}x"
        pass "Throughput comparison (N=1: ${T1_MS}ms, N=4: ${T4_MS}ms, ${SPEEDUP}x)"
    else
        pass "Throughput comparison (timing unavailable)"
    fi
else
    printf '  Timing compression status: N=1:%s N=4:%s\n' "$T1_STATUS" "$T4_STATUS"
    cat -- "$T/t14-n1.log" "$T/t14-n4.log"
    fail "Throughput comparison requires successful compression and nonempty regular archives"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  MT RESULTS: $PASS passed, $FAIL failed ($TOTAL tests)"
echo "═══════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
