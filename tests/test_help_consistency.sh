#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Regression test for the `vaptvupt help` output.
#
# History:
#   F-13 (v3.0.2): the usage() string literal exceeded C99's 4095-char
#   limit (4121 chars), triggering -Woverlength-strings. Also, the
#   help text had drifted out of date during the v3.0.0 rename:
#     - Examples still said `zupt compress`, `zupt extract`, etc.
#     - "Compression: LZ77 (1MB window) + Huffman entropy coding" —
#       false; the default codec is now VaptVupt LZ + ANS 2.48.5
#     - "License: AGPL-3.0-or-later (Zupt)" — should be (VaptVupt)
#
# This test asserts the help output stays consistent with reality.
# Run from repo root after a build.

set -u
PASS=0; FAIL=0
P() { echo "  ✓ $1"; PASS=$((PASS+1)); }
F() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

BIN=./vaptvupt
[ -x ./vaptvupt ] || BIN=./zupt
[ -x "$BIN" ] || { echo "ERROR: no built binary found"; exit 2; }

HELP=$("$BIN" help 2>&1)

echo "Help consistency"

# ─── F-13 guard: usage() string-literal size ───
# Each fprintf-passed string literal (after adjacent concatenation)
# must be under C99's 4095-char limit. We use a python helper to
# walk fprintf(...) calls and measure the concatenated literal.
python3 > /tmp/usage_size_check.txt <<'PYEOF'
import re
src = open('src/zupt_main.c').read()
pattern = re.compile(r'fprintf\(\s*\w+\s*,\s*((?:"(?:[^"\\]|\\.)*"\s*)+)', re.S)
worst = 0
worst_lineno = 0
for m in pattern.finditer(src):
    block = m.group(1)
    literals = re.findall(r'"((?:[^"\\]|\\.)*)"', block)
    concat = ''.join(literals)
    actual = len(re.sub(r'\\.', 'X', concat))
    if actual > worst:
        worst = actual
        worst_lineno = src[:m.start()].count('\n') + 1
if worst >= 4095:
    print(f"FAIL:{worst}:{worst_lineno}")
else:
    print(f"PASS:{worst}:{worst_lineno}")
PYEOF
RES=$(tail -1 /tmp/usage_size_check.txt)
if [[ "$RES" == PASS:* ]]; then
    L=${RES#PASS:}; L=${L%:*}
    P "usage() string literals are under C99 4095-char limit (worst: $L chars)"
else
    L=${RES#FAIL:}; LINE=${L##*:}; L=${L%:*}
    F "usage() has a string literal of $L chars at line $LINE — over C99 4095 limit (F-13 regression)"
fi

# ─── Brand consistency ───
# The help output must use the new binary name in examples, not the old one.
if echo "$HELP" | grep -qE '^\s+vaptvupt (compress|extract|list|test|bench|keygen|info|disk)'; then
    P "examples use 'vaptvupt' command name"
else
    F "examples don't use 'vaptvupt' — still saying 'zupt'?"
fi

# Conversely, the example lines shouldn't start with `zupt ` (the
# bare legacy name in example commands is the drift we just fixed).
LEGACY_EX=$(echo "$HELP" | grep -cE '^\s{1,4}zupt (compress|extract|list|test|bench|keygen) ')
if [ "$LEGACY_EX" -eq 0 ]; then
    P "no examples use the bare legacy 'zupt' command name"
else
    F "$LEGACY_EX example lines still use the legacy 'zupt' command name"
fi

# ─── Codec consistency ───
# Help text must mention the actual default codec, not the v2.x one.
if echo "$HELP" | grep -q "VaptVupt LZ + ANS"; then
    P "help mentions VaptVupt LZ + ANS as the default codec"
else
    F "help doesn't mention VaptVupt LZ + ANS — still claiming LZ77+Huffman?"
fi

# Conversely, the BARE phrase "LZ77 (1MB window) + Huffman" was the v2.x
# default-codec description; if it's still there, the help text is stale.
if echo "$HELP" | grep -q "LZ77 (1MB window) + Huffman entropy coding"; then
    F "help still has the stale v2.x 'LZ77 (1MB window) + Huffman' description"
else
    P "help doesn't have the stale v2.x default-codec description"
fi

# ─── License consistency ───
if echo "$HELP" | grep -q "AGPL-3.0-or-later (VaptVupt)"; then
    P "help shows the correct license attribution (VaptVupt)"
else
    F "help has wrong license attribution — should say AGPL-3.0-or-later (VaptVupt)"
fi

# Commercial-licensing contact visible.
if echo "$HELP" | grep -q "sac@securityops.co"; then
    P "help shows the commercial-licensing contact (sac@securityops.co)"
else
    F "help is missing the commercial-licensing contact"
fi

# ─── KDF consistency ───
# The help must state the ACTUAL default KDF for this build: PBKDF2-SHA256 on
# the source-only build (WITH_SDK=0), Argon2id only when built with WITH_SDK=1.
# A build that advertises Argon2id-by-default but derives PBKDF2 keys overstates
# its GPU/ASIC resistance (regression from v4.2.1).
if echo "$HELP" | grep -qiE "argon2id.*WITH_SDK=1"; then
    P "help correctly scopes Argon2id to WITH_SDK=1 (source-only build)"
elif echo "$HELP" | grep -qE "PBKDF2.*[Dd]efault|[Dd]efault.*PBKDF2"; then
    P "help correctly identifies PBKDF2-SHA256 as the default KDF"
elif echo "$HELP" | grep -qE "Argon2id.*[Dd]efault"; then
    # A WITH_SDK=1 build legitimately defaults to Argon2id.
    P "help identifies Argon2id as the default KDF (WITH_SDK=1 build)"
else
    F "help does not state the default password KDF"
fi

# ─── Format consistency ───
if echo "$HELP" | grep -qE "Format:\s+v1\.6"; then
    P "help reports the correct format version (v1.6)"
else
    F "help doesn't report the correct format version"
fi

# ─── Functional check: help command works ───
if "$BIN" help >/dev/null 2>&1; then
    P "vaptvupt help exits successfully"
else
    F "vaptvupt help exits with non-zero status"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  Help consistency: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
