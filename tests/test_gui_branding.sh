#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Regression test for ZUPT GUI branding + licensing.
#
# History: in v3.0.0 the GUI shipped with two documentation/code bugs:
#   1. The about panel described the current GUI simply as MIT even though the
#      current source carried AGPL-3.0-or-later notices. Published earlier MIT
#      grants remain valid for the exact historical material covered by them.
#   2. A version-string parser using `replace("zupt ", "")` which
#      matched the wrong substring after the v3.0.0 rename. The
#      version banner became `vaptvupt 3.0.0 (formerly zupt;
#      renamed in v3.0.0 — INPI Brasil trademark)` and that
#      `replace` chewed up "zupt " inside the parenthetical too.
#
# This test keeps the current about-panel statement aligned with current SPDX
# notices without denying the historical license record, and covers the parser.

set -u
PASS=0; FAIL=0
P() { echo "  ✓ $1"; PASS=$((PASS+1)); }
F() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

GUI=gui/src/zupt_gui.py
[ ! -f "$GUI" ] && { echo "ERROR: $GUI missing — run from repo root"; exit 2; }

echo "GUI branding + licensing"

# ─── Current and historical license checks ───
# The current about-panel implementation must not advertise the current GUI as
# MIT-only. Historical license information belongs in the license notice.
if grep -nE '"MIT"|"MIT [Ll]icense"|        MIT[^A-Za-z]' "$GUI" >/dev/null 2>&1; then
    F "GUI source advertises the current GUI as MIT"
    grep -nE '"MIT"|"MIT [Ll]icense"|        MIT[^A-Za-z]' "$GUI" | sed 's/^/    /'
else
    P "GUI source does not advertise the current GUI as MIT"
fi

# The GUI's own LICENSE-GUI file must be AGPL (or pointed to AGPL).
if [ -f gui/LICENSE-GUI ]; then
    if grep -q "GNU AFFERO GENERAL PUBLIC LICENSE\|AGPL" gui/LICENSE-GUI; then
        P "gui/LICENSE-GUI is AGPL-licensed"
    else
        F "gui/LICENSE-GUI is not AGPL — got: $(head -1 gui/LICENSE-GUI)"
    fi
    # The current notice starts with AGPL, while retaining the factual erratum.
    if head -1 gui/LICENSE-GUI | grep -qE "^MIT License"; then
        F "gui/LICENSE-GUI presents MIT as the current license"
    else
        P "gui/LICENSE-GUI presents AGPL as the current license"
    fi
    if grep -q 'd4660e6539c8b6eeba81751c018217d978fdd618' gui/LICENSE-GUI &&
       grep -q 'v2.2.2' gui/LICENSE-GUI &&
       grep -q 'does not revoke or reinterpret a historical grant' gui/LICENSE-GUI; then
        P "gui/LICENSE-GUI preserves the evidenced historical MIT grant"
    else
        F "gui/LICENSE-GUI is missing the factual historical-license erratum"
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

# Package and promotion gates consume this as a machine-readable identity.
# Keep binding and discovered-CLI diagnostics in the UI rather than appending
# them to the stable --version line.
if [ "$(grep -Fc 'print(f"zupt-gui {ZUPT_VER_NUMBER}' "$GUI")" -eq 1 ] &&
   grep -Fqx '        print(f"zupt-gui {ZUPT_VER_NUMBER}")' "$GUI"; then
    P "GUI --version emits the stable exact product/version line"
else
    F "GUI --version output is not the stable exact product/version line"
fi

# ─── Brand-string check ───
# Release 5.2.2 restores the original ZUPT identity in every current panel.
if grep -q 'QLabel("ZUPT")' "$GUI" &&
   ! grep -q 'QLabel("VAPTVUPT")' "$GUI"; then
    P "GUI uses ZUPT in current QLabel headers"
else
    F "GUI current headers are not consistently branded ZUPT"
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
BIN=${1:-${ZUPT_BIN:-./zupt}}
if [ -x "$BIN" ]; then
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
    echo "  - skipped: ZUPT binary not built — skipping functional version test"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  GUI branding + licensing: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
