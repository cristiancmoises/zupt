#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Regression test for argument order in extract/list/test commands.
# Bug #15 (v2.2.2): options after the positional archive argument were
# silently dropped. e.g. `zupt x arch.zupt -o out` ignored `-o out`.

ZUPT_BIN="$(realpath ./zupt)"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
cd "$TMPDIR"

PASS=0; FAIL=0
chk() {
    if [ $? -eq 0 ]; then echo "  ✓ $1"; PASS=$((PASS+1))
    else echo "  ✗ $1"; FAIL=$((FAIL+1)); fi
}

echo "  [Argument order regression — extract/list/test]"

# Setup
mkdir d
echo "secret content $(date +%s%N)" > d/file.txt
"$ZUPT_BIN" c arch.zupt d/file.txt > /dev/null 2>&1
"$ZUPT_BIN" c -p mypw arch_pw.zupt d/file.txt > /dev/null 2>&1
"$ZUPT_BIN" keygen -o k.key > /dev/null 2>&1
"$ZUPT_BIN" keygen --pub -o p.key -k k.key > /dev/null 2>&1
"$ZUPT_BIN" c --pq p.key arch_pq.zupt d/file.txt > /dev/null 2>&1

# P1: extract -o after archive
mkdir out1
"$ZUPT_BIN" x arch.zupt -o out1 > /dev/null 2>&1
[ -f out1/d/file.txt ] && diff -q d/file.txt out1/d/file.txt > /dev/null
chk "extract: -o after archive"

# P2: extract -o before archive
mkdir out2
"$ZUPT_BIN" x -o out2 arch.zupt > /dev/null 2>&1
[ -f out2/d/file.txt ] && diff -q d/file.txt out2/d/file.txt > /dev/null
chk "extract: -o before archive"

# P3: extract password options after archive
mkdir out3
"$ZUPT_BIN" x arch_pw.zupt -p mypw -o out3 > /dev/null 2>&1
[ -f out3/d/file.txt ] && diff -q d/file.txt out3/d/file.txt > /dev/null
chk "extract: -p AND -o after archive"

# P4: extract --pq after archive
mkdir out4
"$ZUPT_BIN" x arch_pq.zupt --pq k.key -o out4 > /dev/null 2>&1
[ -f out4/d/file.txt ] && diff -q d/file.txt out4/d/file.txt > /dev/null
chk "extract: --pq after archive"

# P5: list -p after archive (encrypted archive lists files)
out=$("$ZUPT_BIN" l arch_pw.zupt -p mypw 2>&1)
echo "$out" | grep -q "file.txt"
chk "list: -p after archive"

# P6: list -p before archive
out=$("$ZUPT_BIN" l -p mypw arch_pw.zupt 2>&1)
echo "$out" | grep -q "file.txt"
chk "list: -p before archive"

# P7: test -p after archive
out=$("$ZUPT_BIN" t arch_pw.zupt -p mypw 2>&1)
echo "$out" | grep -q "0 failed"
chk "test: -p after archive"

# P8: test -p before archive
out=$("$ZUPT_BIN" t -p mypw arch_pw.zupt 2>&1)
echo "$out" | grep -q "0 failed"
chk "test: -p before archive"

echo
echo "  ───────────────────────────────────────"
echo "  Argument order regression: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ $FAIL -eq 0 ]
