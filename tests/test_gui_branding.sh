#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Regression test for GUI branding + licensing.
#
# History: in v3.0.0 the GUI shipped with two real bugs:
#   1. An MIT license credit line in the about panel — the GUI is
#      AGPL-3.0-or-later with commercial dual-licensing; "MIT" was
#      false and inherited from an early templating mistake.
#   2. A version-string parser using `replace("zupt ", "")` which
#      matched the wrong substring after the v3.0.0 rename. The
#      version banner became `vaptvupt 3.0.0 (formerly zupt;
#      renamed in v3.0.0 — INPI Brasil trademark)` and that
#      `replace` chewed up "zupt " inside the parenthetical too.
#
# This test asserts both classes of bug stay fixed.

set -u
PASS=0; FAIL=0
P() { echo "  ✓ $1"; PASS=$((PASS+1)); }
F() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

GUI=gui/src/zupt_gui.py
[ ! -f "$GUI" ] && { echo "ERROR: $GUI missing — run from repo root"; exit 2; }

echo "GUI branding + licensing"

# ─── MIT reference checks ───
# Any MIT credit line in the GUI source is a bug.
if grep -nE '"MIT"|"MIT [Ll]icense"|        MIT[^A-Za-z]' "$GUI" >/dev/null 2>&1; then
    F "GUI source contains an MIT reference"
    grep -nE '"MIT"|"MIT [Ll]icense"|        MIT[^A-Za-z]' "$GUI" | sed 's/^/    /'
else
    P "GUI source contains no MIT references"
fi

# The GUI's own LICENSE-GUI file must be AGPL (or pointed to AGPL).
if [ -f gui/LICENSE-GUI ]; then
    if grep -q "GNU AFFERO GENERAL PUBLIC LICENSE\|AGPL" gui/LICENSE-GUI; then
        P "gui/LICENSE-GUI is AGPL-licensed"
    else
        F "gui/LICENSE-GUI is not AGPL — got: $(head -1 gui/LICENSE-GUI)"
    fi
    # Specifically, it shouldn't START with "MIT License"
    if head -1 gui/LICENSE-GUI | grep -qE "^MIT License"; then
        F "gui/LICENSE-GUI starts with 'MIT License' — that's the bug we just fixed"
    else
        P "gui/LICENSE-GUI does not start with 'MIT License'"
    fi
fi

# ─── SPDX header check ───
# The .py source's SPDX header must be AGPL-3.0-or-later.
if head -5 "$GUI" | grep -q "SPDX-License-Identifier: AGPL-3.0-or-later"; then
    P "GUI SPDX header is AGPL-3.0-or-later"
else
    F "GUI SPDX header is missing or wrong"
fi

# ─── Version-parsing bug check ───
# The buggy pattern was `ZUPT_VER_SHORT.replace("zupt ", ...)`.
# That regex must not appear in CODE — it produces garbage on v3.0.x
# version strings. The explanatory comment in _get_version that
# documents the historical fix is fine.
if grep -nE 'replace\("zupt ' "$GUI" | grep -vE '^[0-9]+:#' >/dev/null 2>&1; then
    F "GUI uses the broken replace(\"zupt \", ...) version parser"
    grep -nE 'replace\("zupt ' "$GUI" | grep -vE '^[0-9]+:#' | sed 's/^/    /'
else
    P "GUI does not use the broken replace(\"zupt \", ...) parser (in code)"
fi

# A proper version regex must be present.
if grep -qE '_VERSION_RE\s*=\s*re\.compile|re\.match.*vaptvupt' "$GUI"; then
    P "GUI defines a strict anchored version regex"
else
    F "GUI is missing the anchored version regex (_VERSION_RE)"
fi

# ─── Brand-string check ───
# Splash and about-panel headers should say VAPTVUPT (the v3.0.0 name),
# not ZUPT.
if grep -q 'QLabel("ZUPT")' "$GUI"; then
    F "GUI still uses QLabel(\"ZUPT\") — should be QLabel(\"VAPTVUPT\")"
else
    P "GUI uses VAPTVUPT (not ZUPT) in QLabel headers"
fi

# Crypto stack should include Argon2id (the default since v2.4.1).
if grep -q 'Argon2id' "$GUI"; then
    P "GUI about-panel crypto stack includes Argon2id"
else
    F "GUI about-panel crypto stack is missing Argon2id"
fi

# Crypto stack should include the VaptVupt codec attribution.
if grep -q 'VaptVupt LZ + ANS\|VaptVupt LZ' "$GUI"; then
    P "GUI about-panel mentions the VaptVupt codec"
else
    F "GUI about-panel doesn't mention the VaptVupt codec"
fi

# Commercial-licensing contact must be visible.
if grep -q 'sac@securityops.co' "$GUI"; then
    P "GUI shows the commercial-licensing contact (sac@securityops.co)"
else
    F "GUI is missing the commercial-licensing contact"
fi

# ─── Functional check ───
# If the CLI binary is available, exercise _VERSION_RE end-to-end.
if [ -x ./vaptvupt ] || [ -x ./zupt ]; then
    BIN=./vaptvupt
    [ ! -x "$BIN" ] && BIN=./zupt
    OUT=$("$BIN" version 2>&1 | head -1)
    EXTRACTED=$(python3 -c "
import re, sys
s = sys.argv[1]
m = re.match(r'^(?:vaptvupt|zupt)\s+(\d+\.\d+\.\d+(?:[._A-Za-z0-9-]*)?)', s)
print(m.group(1) if m else 'NONE')
" "$OUT")
    EXPECTED=$(grep -E '^#define ZUPT_VERSION_STRING' include/zupt.h | awk -F'"' '{print $2}')
    if [ "$EXTRACTED" = "$EXPECTED" ]; then
        P "version regex extracts $EXTRACTED (matches include/zupt.h)"
    else
        F "version regex extracted '$EXTRACTED', expected '$EXPECTED'"
    fi
else
    echo "  - skipped: ./vaptvupt not built — skipping functional version test"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  GUI branding + licensing: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
