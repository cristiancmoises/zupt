#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Result handling only. These synthetic reports do not prove the C helper.
set -eu

if [ "${0##*/}" = frama-reader-fixture ]; then
    if [ "${1:-}" = -version ]; then
        case "$FRAMA_READER_CASE" in
            version) printf '28.0 (Nickel)\n' ;;
            *) printf '29.0 (Copper)\n' ;;
        esac
        exit 0
    fi
    report=
    while [ "$#" -gt 0 ]; do
        if [ "$1" = -wp-report-json ]; then report=$2; break; fi
        shift
    done
    python3 - "$report" "$FRAMA_READER_CASE" "$FRAMA_READER_SOURCE" "$FRAMA_READER_PROFILE" <<'PY'
import json
import sys
from pathlib import Path

path, case, source, profile = sys.argv[1:]
take_suffixes = [
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
]
init_suffixes = [
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
]
frequency_suffixes = [
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
]
logarithm_suffixes = (
    ["ensures_result_range", "ensures_zero"]
    + [f"ensures_exact_{case}" for case in range(12)]
    + [
        f"loop_invariant_{name}_{phase}"
        for name in [f"case{case}" for case in range(12)] + ["range", "zero", "mask_or_bound"]
        for phase in ("preserved", "established")
    ]
    + [
        "assert_rte_signed_overflow", "loop_assigns",
        "assigns_part1", "assigns_part2",
        "loop_variant_decrease", "loop_variant_positive",
    ]
)
functions = (
    [("validated_symbol_count", frequency_suffixes)]
    if profile == "frequency"
    else [("ilog2", logarithm_suffixes)]
    if profile == "logarithm"
    else [("ans_br_init", init_suffixes), ("ans_br_take", take_suffixes)]
)
rows = [
    {
        "goal": "typed_" + function + "_" + suffix,
        "file": source,
        "line": 1,
        "function": function,
        "smoke": False,
        "passed": True,
        "verdict": "valid",
        "provers": [{"prover": "Z3:4.12.2", "time": 0.0, "success": 1}],
        "proved": 1,
    }
    for function, suffixes in functions
    for suffix in suffixes
]
for row in rows:
    if "loop_invariant_mask_or_bound_" in row["goal"]:
        row["tactics"] = 1
if case in ("old-partial", "unknown"):
    target = rows[0]
    if case == "unknown" and profile == "logarithm":
        target = next(
            row for row in rows
            if row["goal"] == "typed_ilog2_loop_invariant_mask_or_bound_preserved"
        )
    target.update(passed=False, verdict="unknown", proved=0)
elif case in ("single-subgoal", "partial-subgoals", "boolean-subgoals", "zero-subgoals"):
    rows[0].update(
        tactics=1,
        subgoals={
            "single-subgoal": 1,
            "partial-subgoals": 2,
            "boolean-subgoals": True,
            "zero-subgoals": 0,
        }[case],
    )
elif case == "duplicate-goal":
    rows[-1] = rows[0]
elif case == "missing-goal":
    rows.pop()
elif case == "extra-goal":
    rows.append(dict(rows[0], goal="foreign"))
elif case == "wrong-goal":
    rows[0]["goal"] = "foreign"
elif case == "wrong-function":
    rows[0]["function"] = "other"
elif case == "swapped-functions":
    rows[0]["function"] = "ans_br_take"
elif case in ("old-take-only", "missing-init"):
    rows = rows[len(init_suffixes) :]
elif case == "wrong-file":
    rows[0]["file"] = "/other/src/vv_ans.c"
elif case == "smoke":
    rows[0]["smoke"] = True
elif case == "wrong-verdict":
    rows[0]["verdict"] = "invalid"
elif case == "numeric-pass":
    rows[0]["passed"] = 1
elif case == "boolean-proved":
    rows[0]["proved"] = True
elif case == "wrong-prover":
    rows[0]["provers"][0]["prover"] = "Z3:4.14.0"
elif case == "unsuccessful-prover":
    rows[0]["provers"][0]["success"] = 0
elif case == "negative-time":
    rows[0]["provers"][0]["time"] = -1
elif case == "nan":
    rows[0]["provers"][0]["time"] = float("nan")
elif case == "string-number":
    rows[0]["provers"][0]["time"] = "0."
text = json.dumps(rows)
if case == "duplicate-key":
    text = text.replace('"smoke": false', '"smoke": false, "smoke": false', 1)
elif case == "trailing-junk":
    text += "junk"
elif case == "malformed-number":
    text = text.replace('"time": 0.0', '"time": 1.', 1)
elif case == "zero-dot":
    text = text.replace('"time": 0.0', '"time": 0.')
elif case == "truncated":
    text = text[:-1]
elif case == "empty-report":
    text = ""
elif case == "wrong-type":
    text = "{}"
if case != "missing-report":
    Path(path).write_text(text)
goal_count = {"reader": 34, "frequency": 25, "logarithm": 52}[profile]
summary = f"{goal_count - 1} / {goal_count}" if case == "old-partial" else f"{goal_count} / {goal_count}"
if case == "old-take-only":
    summary = "20 / 20"
if case != "missing-summary":
    print("[wp] Proved goals:   " + summary)
if case == "duplicate-summary":
    print("[wp] Proved goals:   " + summary)
if case == "warning":
    print("[kernel] Warning: synthetic diagnostic")
if case == "external-warning":
    print("/tmp/input.c:1: warning: synthetic diagnostic")
if case == "timeout-text":
    print("[wp] [Z3] Goal timed out")
if case == "failure-text":
    print("[wp] Failure: synthetic diagnostic")
PY
    case "$FRAMA_READER_CASE" in
        status) exit 23 ;;
        timeout) exit 124 ;;
    esac
    exit 0
fi

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
self="$repo_root/tests/test_frama_ans_reader_wrapper.sh"
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-reader-wrapper.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cp -- "$self" "$test_tmp/frama-reader-fixture"
chmod +x "$test_tmp/frama-reader-fixture"
total=0
failed=0
for profile in reader frequency logarithm; do
for test_case in clean zero-dot single-subgoal partial-subgoals boolean-subgoals zero-subgoals \
    old-partial old-take-only missing-init swapped-functions \
    unknown duplicate-goal missing-goal extra-goal \
    wrong-goal wrong-function wrong-file smoke wrong-verdict numeric-pass boolean-proved \
    wrong-prover unsuccessful-prover negative-time nan string-number duplicate-key \
    trailing-junk malformed-number truncated empty-report wrong-type missing-report \
    missing-summary duplicate-summary warning external-warning timeout-text failure-text \
    status timeout version missing parser-missing; do
    total=$((total + 1))
    analyzer="$test_tmp/frama-reader-fixture"
    parser=python3
    expected=1
    case "$test_case" in
        clean|zero-dot|single-subgoal) expected=0 ;;
        status) expected=23 ;;
        timeout) expected=124 ;;
        missing) analyzer="$test_tmp/no-analyzer"; expected=127 ;;
        parser-missing) parser="$test_tmp/no-parser"; expected=127 ;;
    esac
    actual=0
    FRAMA_C="$analyzer" PYTHON="$parser" FRAMA_READER_CASE="$test_case" FRAMA_READER_PROFILE="$profile" \
        FRAMA_READER_SOURCE="$repo_root/src/vv_ans.c" \
        sh "$repo_root/tests/test_frama_ans_reader.sh" "$profile" >"$test_tmp/result.log" 2>&1 || actual=$?
    marker=0
    wanted_text='PASS: Frama-C ANS reader initialization/extraction, 30 exact WP goals (conditional scope)'
    if [ "$profile" = frequency ]; then
        wanted_text='PASS: Frama-C ANS frequency validation, 23 exact WP goals (conditional scope)'
    elif [ "$profile" = logarithm ]; then
        wanted_text='PASS: Frama-C ANS bounded logarithm, 50 exact WP goals (conditional scope)'
    fi
    grep -Fq "$wanted_text" \
        "$test_tmp/result.log" || marker=$?
    wanted_marker=1
    if [ "$expected" -eq 0 ]; then wanted_marker=0; fi
    raw_report=0
    if [ "$test_case" = old-partial ]; then
        grep -Fxq 'BEGIN_WP_RAW_JSON' "$test_tmp/result.log" &&
            grep -Fxq 'END_WP_RAW_JSON' "$test_tmp/result.log" || raw_report=1
    fi
    if [ "$actual" -ne "$expected" ] || [ "$marker" -ne "$wanted_marker" ] || [ "$raw_report" -ne 0 ]; then
        cat "$test_tmp/result.log" >&2
        printf 'FAIL: %s result %s returned %s, expected %s (marker %s/%s)\n' \
            "$profile" "$test_case" "$actual" "$expected" "$marker" "$wanted_marker" >&2
        failed=$((failed + 1))
    else
        printf 'PASS: synthetic %s result %s\n' "$profile" "$test_case"
    fi
done
done
printf 'RESULT: %s synthetic ANS WP result cases, %s failures; no C analysis\n' "$total" "$failed"
[ "$failed" -eq 0 ]
