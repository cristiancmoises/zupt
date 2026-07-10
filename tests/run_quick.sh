#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
set +e
Z="./zupt"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/d"; echo "hello" > "$T/d/a.txt"
dd if=/dev/urandom bs=1024 count=10 of="$T/d/b.bin" 2>/dev/null; touch "$T/d/e.txt"
P=0; F=0; ok() { echo "  OK:   $1"; P=$((P+1)); }; fl() { echo "  FAIL: $1"; F=$((F+1)); }
echo "═══ Quick Test (9 tests) ═══"
$Z compress "$T/1.zupt" "$T/d/" 2>/dev/null && $Z extract -o "$T/o1" "$T/1.zupt" 2>/dev/null
E=$(find "$T/o1" -name a.txt -type f 2>/dev/null|head -1); [ -n "$E" ] && diff -q "$T/d/a.txt" "$E" >/dev/null 2>&1 && ok "Normal" || fl "Normal"
$Z compress --solid "$T/2.zupt" "$T/d/" 2>/dev/null && $Z extract -o "$T/o2" "$T/2.zupt" 2>/dev/null
E=$(find "$T/o2" -name a.txt -type f 2>/dev/null|head -1); [ -n "$E" ] && diff -q "$T/d/a.txt" "$E" >/dev/null 2>&1 && ok "Solid" || fl "Solid"
$Z compress -p pw "$T/3.zupt" "$T/d/" 2>/dev/null && $Z extract -o "$T/o3" -p pw "$T/3.zupt" 2>/dev/null
E=$(find "$T/o3" -name a.txt -type f 2>/dev/null|head -1); [ -n "$E" ] && diff -q "$T/d/a.txt" "$E" >/dev/null 2>&1 && ok "Encrypted" || fl "Encrypted"
$Z extract -o "$T/o4" -p WRONG "$T/3.zupt" 2>/dev/null; [ $? -ne 0 ] && ok "Wrong pw" || fl "Wrong pw"
$Z compress -t 4 "$T/5.zupt" "$T/d/" 2>/dev/null && $Z extract -o "$T/o5" "$T/5.zupt" 2>/dev/null
E=$(find "$T/o5" -name a.txt -type f 2>/dev/null|head -1); [ -n "$E" ] && diff -q "$T/d/a.txt" "$E" >/dev/null 2>&1 && ok "MT" || fl "MT"
$Z compress -f "$T/6.zupt" "$T/d/" 2>/dev/null && $Z extract -o "$T/o6" "$T/6.zupt" 2>/dev/null
E=$(find "$T/o6" -name a.txt -type f 2>/dev/null|head -1); [ -n "$E" ] && diff -q "$T/d/a.txt" "$E" >/dev/null 2>&1 && ok "Fast" || fl "Fast"
$Z compress -s "$T/7.zupt" "$T/d/" 2>/dev/null && $Z extract -o "$T/o7" "$T/7.zupt" 2>/dev/null
E=$(find "$T/o7" -name a.txt -type f 2>/dev/null|head -1); [ -n "$E" ] && diff -q "$T/d/a.txt" "$E" >/dev/null 2>&1 && ok "Store" || fl "Store"
$Z keygen -o "$T/k.key" 2>/dev/null && $Z keygen --pub -o "$T/p.key" -k "$T/k.key" 2>/dev/null
$Z compress --pq "$T/p.key" "$T/8.zupt" "$T/d/" 2>/dev/null && $Z extract --pq "$T/k.key" -o "$T/o8" "$T/8.zupt" 2>/dev/null
E=$(find "$T/o8" -name a.txt -type f 2>/dev/null|head -1); [ -n "$E" ] && diff -q "$T/d/a.txt" "$E" >/dev/null 2>&1 && ok "PQ" || fl "PQ"
# Full post-quantum (ML-KEM-768 only, no X25519) round-trip.
$Z keygen --pq-only -o "$T/kq.key" 2>/dev/null && $Z keygen --pub --pq-only -o "$T/pq.key" -k "$T/kq.key" 2>/dev/null
$Z compress --pq-only "$T/pq.key" "$T/9.zupt" "$T/d/" 2>/dev/null && $Z extract --pq-only "$T/kq.key" -o "$T/o9" "$T/9.zupt" 2>/dev/null
E=$(find "$T/o9" -name a.txt -type f 2>/dev/null|head -1); [ -n "$E" ] && diff -q "$T/d/a.txt" "$E" >/dev/null 2>&1 && ok "PQ-only" || fl "PQ-only"
R=$($Z test "$T/1.zupt" 2>&1); echo "$R"|grep -q "0 failed" && ok "Integrity" || fl "Integrity"
# F-01 (2.2.4): every help command verb starts its own line.
# Pre-fix output ran "keygen … Key generation  zupt version" on one
# wrapped line due to a missing \n in src/zupt_main.c:41.
HC=$($Z help 2>&1 | grep -cE '^  (vaptvupt|zupt) ')
[ "$HC" -ge 10 ] && ok "Help command lines ($HC)" || fl "Help command lines ($HC, need ≥10)"
echo ""; echo "  Results: $P passed, $F failed (11 tests)"; [ "$F" -eq 0 ] && exit 0 || exit 1
