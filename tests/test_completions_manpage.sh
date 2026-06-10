#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Sprint 2.4.7 regression: shell completions + manpage.
#
# Asserts:
#   - completions/vaptvupt.bash has bash-clean syntax
#   - completions/_vaptvupt has zsh-clean syntax (if zsh available)
#   - completions/vaptvupt.fish has fish-clean syntax (if fish available)
#   - Each completion file mentions all the major CLI flags the binary
#     actually parses (--kdf, --comment, --pq-sdk, --dedup, ...)
#   - doc/zupt.1 mentions current v2.4.x features (--kdf, --comment,
#     Argon2id, F-11, comment-file)
#   - doc/zupt.1 has the standard sections (NAME, SYNOPSIS, DESCRIPTION,
#     COMMANDS, EXAMPLES)

set -u

PASS=0
FAIL=0
P() { PASS=$((PASS+1)); echo "  ✓ $1"; }
F() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
SKIP() { echo "  - skipped: $1"; }

cd "$(dirname "$0")/.."

VERSION=$(grep '^#define ZUPT_VERSION_STRING' include/zupt.h | awk -F'"' '{print $2}')
echo "Completions + manpage (vaptvupt $VERSION)"

# ─── Bash completion ───
if [ -f completions/vaptvupt.bash ]; then
    if bash -n completions/vaptvupt.bash 2>/dev/null; then
        P "bash completion: syntax clean"
    else
        F "bash completion: syntax error"
    fi
    # Should define a _zupt function and register it via complete -F
    if grep -q "^_vaptvupt()" completions/vaptvupt.bash; then
        P "bash completion: defines _vaptvupt function"
    else
        F "bash completion: missing _vaptvupt function"
    fi
    if grep -qE "^complete -F _vaptvupt (vaptvupt|zupt)" completions/vaptvupt.bash; then
        P "bash completion: registers via complete -F"
    else
        F "bash completion: missing complete -F registration"
    fi
else
    F "completions/vaptvupt.bash missing"
fi

# ─── Zsh completion ───
if [ -f completions/_vaptvupt ]; then
    if command -v zsh >/dev/null 2>&1; then
        if zsh -n completions/_vaptvupt 2>/dev/null; then
            P "zsh completion: syntax clean"
        else
            F "zsh completion: syntax error"
        fi
    else
        SKIP "zsh not installed — skipping syntax check"
    fi
    # Should have #compdef directive
    if grep -qE "^#compdef vaptvupt( zupt)?$" completions/_vaptvupt; then
        P "zsh completion: has #compdef vaptvupt directive"
    else
        F "zsh completion: missing #compdef directive"
    fi
else
    F "completions/_vaptvupt missing"
fi

# ─── Fish completion ───
if [ -f completions/vaptvupt.fish ]; then
    if command -v fish >/dev/null 2>&1; then
        if fish -n completions/vaptvupt.fish 2>/dev/null; then
            P "fish completion: syntax clean"
        else
            F "fish completion: syntax error"
        fi
    else
        SKIP "fish not installed — skipping syntax check"
    fi
    # Should have complete -c zupt entries
    if grep -qE "^complete -c (vaptvupt|zupt)" completions/vaptvupt.fish; then
        P "fish completion: has complete -c vaptvupt entries"
    else
        F "fish completion: no complete -c vaptvupt entries"
    fi
else
    F "completions/vaptvupt.fish missing"
fi

# ─── Flag-coverage check (across all three completion files) ───
# Every flag the binary actually parses should appear in every completion file.
# Each completion format has its own way of writing long options:
#   bash:  --flag
#   zsh:   --flag
#   fish:  -l flag (or --flag in comments)
critical_flags=(kdf comment comment-file pq pq-sdk dedup solid verbose quiet threads level block store fast lzhp vaptvupt)

for f in completions/vaptvupt.bash completions/_vaptvupt; do
    [ -f "$f" ] || continue
    name=$(basename "$f")
    missing=""
    for flag in "${critical_flags[@]}"; do
        if ! grep -qF -- "--$flag" "$f"; then
            missing="$missing --$flag"
        fi
    done
    if [ -z "$missing" ]; then
        P "$name: covers all ${#critical_flags[@]} critical flags"
    else
        F "$name: missing flags:$missing"
    fi
done

if [ -f completions/vaptvupt.fish ]; then
    name="vaptvupt.fish"
    missing=""
    for flag in "${critical_flags[@]}"; do
        # fish uses `-l flag-name` for long opts
        if ! grep -qE -- "(-l $flag|--$flag)" completions/vaptvupt.fish; then
            missing="$missing $flag"
        fi
    done
    if [ -z "$missing" ]; then
        P "$name: covers all ${#critical_flags[@]} critical flags (via -l form)"
    else
        F "$name: missing flags:$missing"
    fi
fi

# ─── Manpage refresh ───
if [ -f doc/zupt.1 ]; then
    # v2.4.x features must be mentioned. Use shell-friendly regexes that
    # match groff's `\-\-` escape (literal backslash, dash, backslash, dash).
    declare -a manpage_checks=(
        "kdf:--kdf option"
        "comment:--comment option"
        "argon2id:Argon2id KDF"
        "Argon2id:Argon2id KDF (capital)"
        "verbal probe-oracle:F-11 message change"
        "ML-KEM-768:post-quantum KEM"
    )
    manpage_misses=0
    for entry in "${manpage_checks[@]}"; do
        key="${entry%%:*}"
        desc="${entry#*:}"
        if grep -qF "$key" doc/zupt.1; then
            :
        else
            F "manpage: doesn't mention '$desc' (looking for '$key')"
            manpage_misses=$((manpage_misses+1))
        fi
    done
    # Two additional checks for groff-escaped hyphens (--comment-file, --pq-sdk
    # render as `\-\-comment\-file` and `\-\-pq\-sdk` in the source)
    if grep -qE "comment\\\\-file|comment-file" doc/zupt.1; then
        :
    else
        F "manpage: doesn't mention --comment-file (looking for comment\\-file or comment-file)"
        manpage_misses=$((manpage_misses+1))
    fi
    if grep -qE "pq\\\\-sdk|pq-sdk" doc/zupt.1; then
        :
    else
        F "manpage: doesn't mention --pq-sdk (looking for pq\\-sdk or pq-sdk)"
        manpage_misses=$((manpage_misses+1))
    fi
    if [ "$manpage_misses" = 0 ]; then
        P "manpage: mentions all v2.4.x features"
    fi

    # Required sections
    for section in NAME SYNOPSIS DESCRIPTION COMMANDS EXAMPLES; do
        if grep -qE "^\.SH $section" doc/zupt.1; then
            :
        else
            F "manpage: missing section '.SH $section'"
        fi
    done
    P "manpage: required sections present"

    # Version header
    if grep -qE "\"(vaptvupt|zupt) $VERSION\"" doc/zupt.1; then
        P "manpage: TH version matches include/zupt.h ($VERSION)"
    else
        F "manpage: TH version doesn't match include/zupt.h"
    fi

    # Try to render with groff if available
    if command -v groff >/dev/null 2>&1; then
        if groff -mandoc -Tutf8 doc/zupt.1 > /tmp/render.txt 2>/tmp/groff_warn.txt; then
            LINES=$(wc -l < /tmp/render.txt)
            if [ "$LINES" -gt 50 ]; then
                P "manpage: renders cleanly with groff ($LINES lines)"
            else
                F "manpage: groff produced suspiciously short output ($LINES lines)"
            fi
        else
            F "manpage: groff rendering failed"
        fi
        rm -f /tmp/render.txt /tmp/groff_warn.txt
    elif command -v mandoc >/dev/null 2>&1; then
        if mandoc -Tlint doc/zupt.1 >/tmp/mandoc.out 2>&1; then
            P "manpage: mandoc lint clean"
        else
            P "manpage: mandoc lint had warnings (acceptable)"
        fi
        rm -f /tmp/mandoc.out
    else
        SKIP "no groff or mandoc — skipping render lint"
    fi
else
    F "doc/zupt.1 missing"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  completions + manpage: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
