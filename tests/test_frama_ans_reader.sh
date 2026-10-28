#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -eu
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
frama_c=${FRAMA_C:-frama-c}
python=${PYTHON:-python3}
profile=${1:-reader}
test "$#" -le 1 || exit 2
case "$profile" in
    reader) functions=ans_br_init,ans_br_take; rte_flags= ;;
    frequency) functions=validated_symbol_count; rte_flags=-warn-unsigned-overflow ;;
    logarithm) functions=ilog2; rte_flags=-warn-unsigned-overflow ;;
    *) printf 'ERROR: expected reader, frequency or logarithm WP profile\n' >&2; exit 2 ;;
esac
version=$("$frama_c" -version)
case "$version" in
    '29.0'*) ;;
    *) printf 'ERROR: reader WP gate requires Frama-C 29.0, got %s\n' "$version" >&2; exit 1 ;;
esac
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-reader-wp.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cpp_args="-I\"$repo_root/include\" -DVV_DISABLE_SIMD=1 -DVV_ANS_STANDALONE -D_Alignof=__alignof__"
if [ "$profile" = frequency ]; then
    cpp_args="$cpp_args -DVV_ANS_FREQUENCY_WP=1"
elif [ "$profile" = logarithm ]; then
    cpp_args="$cpp_args -DVV_ANS_LOG_WP=1"
fi
analysis_status=0
set -- -machdep gcc_x86_64 -cpp-extra-args="$cpp_args"
if [ -n "$rte_flags" ]; then
    set -- "$@" "$rte_flags"
fi
set -- "$@" -wp -wp-rte -wp-fct "$functions" -wp-prover z3 -wp-par 1 -wp-timeout 2 \
    -wp-report-json "$test_tmp/wp.json" -wp-out "$test_tmp/wp-out"
if [ "$profile" = logarithm ]; then
    set -- "$@" -wp-auto wp:bitrange -wp-auto-depth 2 -wp-auto-width 4 \
        -wp-session "$test_tmp/wp-session" -wp-script init -wp-script-on-stdout
fi
"$frama_c" "$@" "$repo_root/src/vv_ans.c" >"$test_tmp/wp.log" 2>&1 || analysis_status=$?
cat "$test_tmp/wp.log"
# Preserve raw evidence even when the analyzer or exact-result gate rejects it.
if [ -f "$test_tmp/wp.json" ]; then
    printf 'BEGIN_WP_RAW_JSON\n'
    cat "$test_tmp/wp.json"
    printf '\nEND_WP_RAW_JSON\n'
fi
test "$analysis_status" -eq 0 || exit "$analysis_status"

"$python" - "$test_tmp/wp.log" "$test_tmp/wp.json" "$repo_root/src/vv_ans.c" "$profile" <<'PY'
import hashlib
import json
import math
import re
import sys
from pathlib import Path


def fail(message):
    raise ValueError(message)


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            fail("duplicate JSON key")
        obj[key] = value
    return obj


try:
    log_path, report_path, source_path, profile = sys.argv[1:]
    log = Path(log_path).read_text()
    summaries = re.findall(r"^\[wp\] Proved goals:.*$", log, re.MULTILINE)
    summary_count = {"reader": 34, "frequency": 25, "logarithm": 52}[profile]
    if len(summaries) != 1 or not re.fullmatch(
        rf"\[wp\] Proved goals:\s+{summary_count} / {summary_count}\s*", summaries[0]
    ):
        fail("missing, conflicting or incomplete WP summary")
    if re.search(
        r"\b(?:warning|error|failure|timeout|timed out|unknown)\b", log, re.IGNORECASE
    ):
        fail("analysis diagnostic")
    raw = Path(report_path).read_bytes()
    text = raw.decode("utf-8")
    # Frama-C 29 prints a zero time as 0., outside RFC 8259. Adapt that
    # one numeric spelling outside strings; preserve the raw report verbatim.
    tokens = re.findall(r'"(?:[^"\\]|\\.)*"|[^"]+', text)
    if "".join(tokens) != text:
        fail("malformed JSON string")
    text = "".join(
        token
        if token.startswith('"')
        else re.sub(r"(?<![\w.])0\.(?=[\s,}\]])", "0.0", token)
        for token in tokens
    )
    rows = json.loads(
        text,
        object_pairs_hook=unique_object,
        parse_constant=lambda value: fail("nonfinite JSON number: " + value),
    )
    take_suffixes = {
        "ensures",
        "ensures_2",
        "ensures_3",
        "ensures_4",
        "assert_rte_mem_access",
        "assert_rte_shift",
        "assert_rte_mem_access_2",
        "assert_rte_mem_access_3",
        "assert_rte_shift_2",
        "assert_rte_mem_access_4",
        "assert_rte_mem_access_5",
        "assert_rte_mem_access_6",
        "assert_rte_signed_overflow",
        "assert_rte_signed_overflow_2",
        "assert_rte_mem_access_7",
        "assigns_part1",
        "assigns_part2",
        "assigns_part3",
    }
    init_suffixes = {
        "ensures",
        "ensures_2",
        "assert_rte_mem_access",
        "assert_rte_mem_access_2",
        "assert_rte_mem_access_3",
        "assert_rte_mem_access_4",
        "assert_rte_mem_access_5",
        "assigns_part1",
        "assigns_part2",
        "assigns_part3",
        "assigns_part4",
        "assigns_part5",
    }
    frequency_suffixes = {
        "ensures", "ensures_2",
        "loop_invariant_preserved", "loop_invariant_established",
        "loop_invariant_2_preserved", "loop_invariant_2_established",
        "loop_invariant_3_preserved", "loop_invariant_3_established",
        "loop_invariant_4_preserved", "loop_invariant_4_established",
        "assert_rte_mem_access", "assert_rte_mem_access_2", "assert_rte_mem_access_3",
        "assert_rte_signed_overflow",
        "assert_rte_unsigned_overflow", "assert_rte_unsigned_overflow_2",
        "assert_rte_unsigned_overflow_3",
        "loop_assigns", "assigns_part1", "assigns_part2", "assigns_part3",
        "loop_variant_decrease", "loop_variant_positive",
    }
    logarithm_suffixes = (
        {"ensures_result_range", "ensures_zero"}
        | {f"ensures_exact_{case}" for case in range(12)}
        | {
            f"loop_invariant_{name}_{phase}"
            for name in [f"case{case}" for case in range(12)] + ["range", "zero", "mask_or_bound"]
            for phase in ("preserved", "established")
        }
        | {
            "assert_rte_signed_overflow", "loop_assigns",
            "assigns_part1", "assigns_part2",
            "loop_variant_decrease", "loop_variant_positive",
        }
    )
    functions = (
        [("validated_symbol_count", frequency_suffixes)]
        if profile == "frequency"
        else [("ilog2", logarithm_suffixes)]
        if profile == "logarithm"
        else [("ans_br_init", init_suffixes), ("ans_br_take", take_suffixes)]
    )
    expected = {
        "typed_" + function + "_" + suffix: function
        for function, suffixes in functions
        for suffix in suffixes
    }
    if not isinstance(rows, list) or len(rows) != len(expected):
        fail("unexpected WP goal count")
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            fail("invalid WP row")
        goal = row.get("goal")
        if not isinstance(goal, str) or goal not in expected or goal in seen:
            fail("missing, duplicated or foreign goal")
        seen.add(goal)
        if (
            row.get("function") != expected[goal]
            or row.get("file") != source_path
            or row.get("smoke") is not False
            or row.get("passed") is not True
            or row.get("verdict") != "valid"
            or type(row.get("proved")) is not int
            or row["proved"] != 1
            or type(row.get("subgoals", 1)) is not int
            or row.get("subgoals", 1) != 1
        ):
            fail("unproved or mismatched goal")
        provers = row.get("provers")
        if not isinstance(provers, list) or not provers:
            fail("missing prover result")
        successes = 0
        for prover in provers:
            if not isinstance(prover, dict) or prover.get("prover") not in (
                "qed",
                # Frama-C 29 reports the solver version verbatim.  Guix
                # currently provides Z3 4.13.0, while older reproducible
                # environments report 4.12.2; both are accepted only when
                # every goal remains proved and valid below.
                "Z3:4.12.2",
                "Z3:4.13.0",
            ):
                fail("unexpected prover")
            elapsed = prover.get("time")
            success = prover.get("success")
            if (
                type(elapsed) not in (int, float)
                or not math.isfinite(elapsed)
                or elapsed < 0
                or type(success) is not int
                or success not in (0, 1)
            ):
                fail("invalid prover result")
            successes += success
        if not successes:
            fail("no successful prover")
    if seen != set(expected):
        fail("incomplete goal set")
    print("WP_RAW_SHA256=" + hashlib.sha256(raw).hexdigest())
except (OSError, UnicodeError, ValueError, TypeError, OverflowError) as error:
    print("FAIL: ANS reader WP result: " + str(error), file=sys.stderr)
    sys.exit(1)
PY
case "$profile" in
    reader) printf 'PASS: Frama-C ANS reader initialization/extraction, 30 exact WP goals (conditional scope)\n' ;;
    frequency) printf 'PASS: Frama-C ANS frequency validation, 23 exact WP goals (conditional scope)\n' ;;
    logarithm) printf 'PASS: Frama-C ANS bounded logarithm, 50 exact WP goals (conditional scope)\n' ;;
esac
