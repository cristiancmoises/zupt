#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
set +e
Z=${1:-./zupt}; T=$(mktemp -d) || exit 1
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/d" && printf 'hello\n' >"$T/d/a.txt" &&
    dd if=/dev/urandom bs=1024 count=10 of="$T/d/b.bin" 2>/dev/null &&
    touch "$T/d/e.txt" || exit 1
P=0; F=0; ok() { echo "  OK:   $1"; P=$((P+1)); }; fl() { echo "  FAIL: $1"; F=$((F+1)); }

check_files() {
    quick_text=$(find "$1" -name a.txt -type f 2>/dev/null) || return 1
    [ -n "$quick_text" ] || return 1
    quick_dir=$(dirname "$quick_text") || return 1
    for quick_file in a.txt b.bin e.txt; do
        [ -f "$quick_dir/$quick_file" ] &&
            cmp "$T/d/$quick_file" "$quick_dir/$quick_file" >/dev/null 2>&1 || return 1
    done
}

echo "═══ Quick Test Suite ═══"
if "$Z" compress "$T/1.zupt" "$T/d/" 2>/dev/null &&
    "$Z" extract -o "$T/o1" "$T/1.zupt" 2>/dev/null &&
    check_files "$T/o1"; then ok "Normal"; else fl "Normal"; fi
if "$Z" compress --solid "$T/2.zupt" "$T/d/" 2>/dev/null &&
    "$Z" extract -o "$T/o2" "$T/2.zupt" 2>/dev/null &&
    check_files "$T/o2"; then ok "Solid"; else fl "Solid"; fi
if "$Z" compress -p pw "$T/3.zupt" "$T/d/" 2>/dev/null &&
    "$Z" extract -o "$T/o3" -p pw "$T/3.zupt" 2>/dev/null &&
    check_files "$T/o3"; then ok "Encrypted"; else fl "Encrypted"; fi
"$Z" extract -o "$T/o4" -p WRONG "$T/3.zupt" 2>/dev/null
if [ $? -eq 1 ]; then ok "Wrong pw"; else fl "Wrong pw"; fi
if "$Z" compress -t 4 "$T/5.zupt" "$T/d/" 2>/dev/null &&
    "$Z" extract -o "$T/o5" "$T/5.zupt" 2>/dev/null &&
    check_files "$T/o5"; then ok "MT"; else fl "MT"; fi
if "$Z" compress -f "$T/6.zupt" "$T/d/" 2>/dev/null &&
    "$Z" extract -o "$T/o6" "$T/6.zupt" 2>/dev/null &&
    check_files "$T/o6"; then ok "Fast"; else fl "Fast"; fi
if "$Z" compress -s "$T/7.zupt" "$T/d/" 2>/dev/null &&
    "$Z" extract -o "$T/o7" "$T/7.zupt" 2>/dev/null &&
    check_files "$T/o7"; then ok "Store"; else fl "Store"; fi
if "$Z" keygen -o "$T/k.key" 2>/dev/null &&
    "$Z" keygen --pub -o "$T/p.key" -k "$T/k.key" 2>/dev/null &&
    "$Z" compress --pq "$T/p.key" "$T/8.zupt" "$T/d/" 2>/dev/null &&
    "$Z" extract --pq "$T/k.key" -o "$T/o8" "$T/8.zupt" 2>/dev/null &&
    check_files "$T/o8"; then ok "PQ"; else fl "PQ"; fi
# Full post-quantum (ML-KEM-768 only, no X25519) round-trip.
if "$Z" keygen --pq-only -o "$T/kq.key" 2>/dev/null &&
    "$Z" keygen --pub --pq-only -o "$T/pq.key" -k "$T/kq.key" 2>/dev/null &&
    "$Z" compress --pq-only "$T/pq.key" "$T/9.zupt" "$T/d/" 2>/dev/null &&
    "$Z" extract --pq-only "$T/kq.key" -o "$T/o9" "$T/9.zupt" 2>/dev/null &&
    check_files "$T/o9"; then ok "PQ-only"; else fl "PQ-only"; fi
if R=$("$Z" test "$T/1.zupt" 2>&1); then
    if printf '%s\n' "$R" | grep -q "0 failed"; then ok "Integrity"; else fl "Integrity"; fi
else
    fl "Integrity"
fi
# F-01 (2.2.4): every help command verb starts its own line.
# Pre-fix output ran "keygen … Key generation  zupt version" on one
# wrapped line due to a missing \n in src/zupt_main.c:41.
if help_output=$("$Z" help 2>&1); then
    HC=$(printf '%s\n' "$help_output" | grep -cE '^  zupt ')
    if [ "$HC" -ge 10 ]; then ok "Help command lines ($HC)"
    else fl "Help command lines ($HC, need ≥10)"
    fi
else
    fl "Help command lines (CLI failed)"
fi
echo ""; echo "  Results: $P passed, $F failed ($((P + F)) tests)"; [ "$F" -eq 0 ] && exit 0 || exit 1
