#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Repeated-suite flake-stress harness.
#
# Runs every short test suite N times (default 50) and aborts on the
# first non-deterministic outcome. Specifically targeted at the audit
# suite, which historically flaked when archive-size variance caused a
# byte-position-based tamper to land in unauthenticated bytes
# (finding F-02 in docs/FINDINGS-2.x.md).
#
# Usage: bash tests/test_audit_flake.sh [N]
#
# Exit codes:
#   0 — all N runs of every targeted suite passed identically.
#   1 — at least one run differed (test is flaky). Output names the run.

set -u
# Default N=20 across 5 suites (~10 min). Pass an arg to override.
# F-02's repro needed 50 runs to be statistically convincing (~10%
# baseline flake rate), but at 20 runs we still have ~88% chance of
# catching a 10%-flake — fine for routine CI. For a hardened audit
# pass, invoke with 50 or 100 for a deeper audit run.
N="${1:-20}"
ZUPT_BIN="${ZUPT_BIN:-./zupt}"

if [ ! -x "$ZUPT_BIN" ]; then
    echo "  ✗ $ZUPT_BIN not found or not executable. Run 'make' first." >&2
    exit 1
fi

run_suite() {
    local name="$1"; shift
    local cmd="$*"
    local pass=0 fail=0 i first_failed_log=""
    echo ""
    echo "  ─── $name × $N ───"
    for i in $(seq 1 "$N"); do
        local out
        out=$(bash -c "$cmd" 2>&1)
        # The convention used by every short suite under tests/ is to
        # finish with "<N> passed, 0 failed" when the suite is green.
        if echo "$out" | grep -qE '[0-9]+ passed, 0 failed'; then
            pass=$((pass+1))
        else
            fail=$((fail+1))
            if [ -z "$first_failed_log" ]; then
                first_failed_log=$(mktemp)
                printf '%s\n' "$out" > "$first_failed_log"
            fi
        fi
    done
    if [ "$fail" -eq 0 ]; then
        echo "  ✓ $name: $pass/$N green (deterministic)"
        return 0
    else
        echo "  ✗ $name: $pass passed, $fail failed — FLAKY"
        echo "  First failing run captured at: $first_failed_log"
        echo "  --- first 30 lines of failing output ---"
        head -30 "$first_failed_log" | sed 's/^/      /'
        return 1
    fi
}

GLOBAL_FAIL=0

run_suite "tests/test_audit.sh"          "bash tests/test_audit.sh"          || GLOBAL_FAIL=1
run_suite "tests/test_path_traversal.sh" "bash tests/test_path_traversal.sh" || GLOBAL_FAIL=1
run_suite "tests/test_arg_order.sh"      "bash tests/test_arg_order.sh"      || GLOBAL_FAIL=1
run_suite "tests/test_block_swap.sh"     "bash tests/test_block_swap.sh"     || GLOBAL_FAIL=1
run_suite "tests/test_dedup_props.sh"    "bash tests/test_dedup_props.sh"    || GLOBAL_FAIL=1

echo ""
if [ "$GLOBAL_FAIL" -eq 0 ]; then
    echo "  ═══════════════════════════════════════════"
    echo "  Flake-stress PASS — $N runs × 5 suites all deterministic"
    echo "  ═══════════════════════════════════════════"
    exit 0
else
    echo "  ═══════════════════════════════════════════"
    echo "  Flake-stress FAIL — see captured log above"
    echo "  ═══════════════════════════════════════════"
    exit 1
fi
