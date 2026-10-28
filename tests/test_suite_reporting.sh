#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# The checks below intentionally match literal shell expansions in source.
# shellcheck disable=SC2016

set -eu

root=${1:-.}
failures=0

check_no_stale_version() {
    script=$root/$1
    if grep -Eq 'ZUPT v[0-9]+([.][0-9]+)* .*Test Suite' "$script"; then
        printf 'FAIL: %s hard-codes a historical suite version\n' "$script" >&2
        failures=$((failures + 1))
    else
        printf 'PASS: %s reports the tested binary version dynamically\n' "$script"
    fi
}

require_line() {
    expected=$1
    script=$root/$2
    description=$3
    if grep -Fqx "$expected" "$script"; then
        printf 'PASS: %s\n' "$description"
    else
        printf 'FAIL: %s\n' "$description" >&2
        failures=$((failures + 1))
    fi
}

check_no_stale_version tests/regression.sh
check_no_stale_version tests/test_threaded.sh
require_line 'echo "  ZUPT Regression Test Suite"' tests/regression.sh \
    'regression suite has its generic heading'
require_line '$ZUPT version 2>&1 | head -1' tests/regression.sh \
    'regression suite reports the tested binary version'
require_line 'echo "  ZUPT Multi-Threaded Test Suite"' tests/test_threaded.sh \
    'threaded suite has its generic heading'
require_line '$ZUPT version 2>&1 | head -1' tests/test_threaded.sh \
    'threaded suite reports the tested binary version'

if grep -Eq 'Quick Test \([0-9]+ tests\)' "$root/tests/run_quick.sh"; then
    printf 'FAIL: quick-suite heading hard-codes its test count\n' >&2
    failures=$((failures + 1))
else
    printf 'PASS: quick-suite heading does not hard-code its test count\n'
fi

require_line 'echo "═══ Quick Test Suite ═══"' tests/run_quick.sh \
    'quick suite has its count-free heading'
require_line 'echo ""; echo "  Results: $P passed, $F failed ($((P + F)) tests)"; [ "$F" -eq 0 ] && exit 0 || exit 1' \
    tests/run_quick.sh 'quick-suite summary derives its test count'

if [ "$failures" -ne 0 ]; then
    printf 'Suite reporting: %d failure(s)\n' "$failures" >&2
    exit 1
fi

printf 'Suite reporting: PASS\n'
