#!/bin/sh
set +e
ZUPT="${1:-./zupt}"
T="/tmp/zupt_pq_$$"; mkdir -p "$T/data"
trap 'rm -rf "$T"' EXIT
echo "Hello PQ World!" > "$T/data/hello.txt"
dd if=/dev/urandom bs=1024 count=50 of="$T/data/rand.bin" 2>/dev/null
yes "PQ test " | head -c 100000 > "$T/data/repeat.txt"
touch "$T/data/empty.txt"
cp "$ZUPT" "$T/data/elf.bin"
PASS=0; FAIL=0
pass() { echo "  OK:   $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
echo "═══════════════════════════════════════"
echo "  PQ Hybrid Encryption Tests"
echo "═══════════════════════════════════════"
$ZUPT keygen -o "$T/priv.key" 2>/dev/null; [ -f "$T/priv.key" ] && pass "keygen" || fail "keygen"
$ZUPT keygen --pub -o "$T/pub.key" -k "$T/priv.key" 2>/dev/null; [ -f "$T/pub.key" ] && pass "pubkey export" || fail "pubkey export"
PS=$(stat -c%s "$T/priv.key" 2>/dev/null); PP=$(stat -c%s "$T/pub.key" 2>/dev/null)
[ "$PS" = "3664" ] && [ "$PP" = "1232" ] && pass "key sizes" || fail "key sizes"
$ZUPT compress --pq "$T/pub.key" "$T/pq.zupt" "$T/data/" 2>/dev/null; [ -f "$T/pq.zupt" ] && pass "PQ compress" || fail "PQ compress"
$ZUPT extract --pq "$T/priv.key" -o "$T/pq_out" "$T/pq.zupt" 2>/dev/null
B=0; for f in hello.txt rand.bin repeat.txt empty.txt elf.bin; do
  E=$(find "$T/pq_out" -name "$f" -type f 2>/dev/null|head -1)
  [ -z "$E" ]||! diff -q "$T/data/$f" "$E" >/dev/null 2>&1 && B=$((B+1))
done; [ "$B" -eq 0 ] && pass "PQ round-trip (5 files)" || fail "PQ round-trip ($B mismatches)"
R=$($ZUPT test --pq "$T/priv.key" "$T/pq.zupt" 2>&1)
echo "$R"|grep -q "0 failed" && pass "PQ integrity" || fail "PQ integrity"
$ZUPT keygen -o "$T/wrong.key" 2>/dev/null
$ZUPT extract --pq "$T/wrong.key" -o "$T/bad" "$T/pq.zupt" 2>/dev/null
[ $? -ne 0 ] && pass "Wrong key rejected" || fail "Wrong key NOT rejected"
$ZUPT compress -p "pw" "$T/pw.zupt" "$T/data/" 2>/dev/null
$ZUPT extract -o "$T/pw_out" -p "pw" "$T/pw.zupt" 2>/dev/null
E=$(find "$T/pw_out" -name "hello.txt" -type f|head -1)
[ -n "$E" ] && diff -q "$T/data/hello.txt" "$E" >/dev/null 2>&1 && pass "Password backward compat" || fail "Password broken"
$ZUPT compress -t 4 --pq "$T/pub.key" "$T/mt.zupt" "$T/data/" 2>/dev/null
$ZUPT extract --pq "$T/priv.key" -o "$T/mt_out" "$T/mt.zupt" 2>/dev/null
B=0; for f in hello.txt rand.bin repeat.txt; do
  E=$(find "$T/mt_out" -name "$f" -type f 2>/dev/null|head -1)
  [ -z "$E" ]||! diff -q "$T/data/$f" "$E" >/dev/null 2>&1 && B=$((B+1))
done; [ "$B" -eq 0 ] && pass "PQ+MT round-trip" || fail "PQ+MT ($B mismatches)"
yes "Large PQ " | head -c 2000000 > "$T/large.txt"
$ZUPT compress --pq "$T/pub.key" "$T/lg.zupt" "$T/large.txt" 2>/dev/null
$ZUPT extract --pq "$T/priv.key" -o "$T/lg_out" "$T/lg.zupt" 2>/dev/null
E=$(find "$T/lg_out" -name "large.txt" -type f|head -1)
[ -n "$E" ] && diff -q "$T/large.txt" "$E" >/dev/null 2>&1 && pass "PQ large (2MB)" || fail "PQ large"
echo ""; echo "  PQ RESULTS: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
