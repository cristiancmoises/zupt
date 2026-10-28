#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Synthetic gate controls only; this does not run the decoder or Frama-C.
set -eu

if [ "${0##*/}" = grep ]; then
    case "$FRAMA_BOUNDS_CASE" in scanner-missing) exit 127 ;; *) exit 2 ;; esac
fi

check_analyzer_arguments() {
    machdep=0 cpp=0 warn=0 eva=0 compact=0 slevel=0 plevel=0 split=0 main=0 ans=0 fixture=0
    need=
    for argument do
        if [ -n "$need" ]; then
            case "$need:$argument" in
                -machdep:gcc_x86_64|-eva-slevel:5000|-eva-plevel:4096|-main:main|\
                -eva-split-return-function:vva_decode_sequences_impl:full,vva_decode_sequences:full,vva_decode_sequences_v2:full) ;;
                *) printf 'ERROR: unexpected analyzer option value\n' >&2; return 1 ;;
            esac
            need=
            continue
        fi
        case "$argument" in
            -machdep) machdep=$((machdep + 1)); need=$argument ;;
            -cpp-extra-args=*)
                cpp=$((cpp + 1))
                case "$argument" in *-DVV_DISABLE_SIMD=1*) ;; *) return 1 ;; esac
                case "$argument" in *-D_Alignof=__alignof__*) ;; *) return 1 ;; esac
                case "$argument" in *VV_ANS_STANDALONE*) return 1 ;; esac ;;
            -warn-invalid-pointer) warn=$((warn + 1)) ;;
            -eva) eva=$((eva + 1)) ;;
            -eva-msg-key=-final-states) compact=$((compact + 1)) ;;
            -eva-slevel) slevel=$((slevel + 1)); need=$argument ;;
            -eva-plevel) plevel=$((plevel + 1)); need=$argument ;;
            -eva-split-return-function) split=$((split + 1)); need=$argument ;;
            -main) main=$((main + 1)); need=$argument ;;
            */src/vv_ans.c) ans=$((ans + 1)) ;;
            */tests/test_ans_decode_bounds.c) fixture=$((fixture + 1)) ;;
            *) printf 'ERROR: unexpected analyzer argument\n' >&2; return 1 ;;
        esac
    done
    [ -z "$need" ] &&
        [ "$machdep$cpp$warn$eva$compact$slevel$plevel$split$main$ans$fixture" = 11111111111 ]
}

emit_witness() {
    number=$1
    case "$FRAMA_BOUNDS_CASE" in missing-witness-"$number") return ;; esac
    case $number in
        1) witness='Frama_C_show_each_metadata: {-2}, {18446744073709551615}' ;;
        2) witness='Frama_C_show_each_literal_tail: {4}, {68}' ;;
        3) witness='Frama_C_show_each_match_tail: {0}, {16}, {20}, {68}' ;;
        4) witness='Frama_C_show_each_match_tail: {1}, {16}, {19}, {67}' ;;
        5) witness='Frama_C_show_each_match_tail: {0}, {8}, {12}, {68}' ;;
        6) witness='Frama_C_show_each_match_tail: {1}, {8}, {11}, {67}' ;;
    esac
    case "$FRAMA_BOUNDS_CASE" in
        wrong-witness-1) [ "$number" != 1 ] || witness='Frama_C_show_each_metadata: {-2}, {0}' ;;
        wrong-witness-2) [ "$number" != 2 ] || witness='Frama_C_show_each_literal_tail: {4}, {67}' ;;
        wrong-witness-3) [ "$number" != 3 ] || witness='Frama_C_show_each_match_tail: {0}, {16}, {19}, {68}' ;;
        wrong-witness-4) [ "$number" != 4 ] || witness='Frama_C_show_each_match_tail: {1}, {16}, {20}, {67}' ;;
        wrong-witness-5) [ "$number" != 5 ] || witness='Frama_C_show_each_match_tail: {0}, {8}, {11}, {68}' ;;
        wrong-witness-6) [ "$number" != 6 ] || witness='Frama_C_show_each_match_tail: {1}, {8}, {12}, {67}' ;;
        nonsingleton-witness) [ "$number" != 2 ] || witness='Frama_C_show_each_literal_tail: {3; 4}, {68}' ;;
        suffix-witness) [ "$number" != 2 ] || witness="$witness extra" ;;
    esac
    if [ "$number" = 1 ]; then
        printf '[eva] /input/fixture.c:89: \n  %s\n' "$witness"
    elif [ "$FRAMA_BOUNDS_CASE" = bare-witness ] && [ "$number" = 2 ]; then
        printf '%s\n' "$witness"
    else
        printf '[eva] /input/fixture.c:43: %s\n' "$witness"
    fi
    case "$FRAMA_BOUNDS_CASE" in
        duplicate-witness-"$number") printf '[eva] /input/fixture.c:43: %s\n' "$witness" ;;
    esac
}

if [ "${0##*/}" = frama-bounds-fixture ]; then
    if [ "${1:-}" = -version ]; then
        case "$FRAMA_BOUNDS_CASE" in version) printf '28.0 (Nickel)\n' ;; *) printf '29.0 (Copper)\n' ;; esac
        exit 0
    fi
    check_analyzer_arguments "$@" || { printf 'ERROR: required production scalar flags missing\n' >&2; exit 24; }
    case "$FRAMA_BOUNDS_CASE" in
        empty) exit 0 ;;
        incomplete) printf '[eva] Analysis started\n'; exit 0 ;;
        warning) printf '[kernel] Warning: synthetic parse diagnostic\n' ;;
        uppercase-warning) printf '[kernel] WARNING: synthetic parse diagnostic\n' ;;
        mixed-case-warning) printf '[kernel] wArNiNg: synthetic parse diagnostic\n' ;;
        external-warning) printf '/tmp/preprocessed.c:1:9: warning: synthetic preprocessor diagnostic\n' ;;
        lowercase-error) printf '[kernel] error: synthetic parse diagnostic\n' ;;
        uppercase-error) printf '[kernel] ERROR: synthetic parse diagnostic\n' ;;
        mixed-case-failure) printf '[eva] FaIlUrE: synthetic analysis diagnostic\n' ;;
        timeout) printf '[eva] timeout while analyzing synthetic fixture\n' ;;
        uppercase-timeout) printf '[eva] TIMEOUT while analyzing synthetic fixture\n' ;;
        timed-out) printf '[eva] analysis timed out on synthetic fixture\n' ;;
        unsupported-acsl-info) printf '[eva] cannot evaluate ACSL term, unsupported ACSL construct: logic function memset\n' ;;
        pruned-body) printf '[eva] <bottom>\n' ;;
        nonreturning-body) printf '[eva] NON TERMINATING FUNCTION\n' ;;
        spec-*) printf '[eva] using specification for function %s\n' "${FRAMA_BOUNDS_CASE#spec-}" ;;
    esac
    if [ "$FRAMA_BOUNDS_CASE" != old-profile ] && [ "$FRAMA_BOUNDS_CASE" != missing-all-witnesses ]; then
        if [ "$FRAMA_BOUNDS_CASE" = reordered-witnesses ]; then
            for number in 1 2 4 3 5 6; do emit_witness "$number"; done
        else
            for number in 1 2 3 4 5 6; do emit_witness "$number"; done
        fi
    fi
    if [ "$FRAMA_BOUNDS_CASE" = unknown-witness ]; then
        printf '[eva] /input/fixture.c:43: Frama_C_show_each_unknown: {0}\n'
    fi
    printf '[eva:summary] ====== ANALYSIS SUMMARY ======\n'
    if [ "$FRAMA_BOUNDS_CASE" = duplicate-summary ]; then printf '[eva:summary] ====== ANALYSIS SUMMARY ======\n'; fi
    case "$FRAMA_BOUNDS_CASE" in
        missing-functions) ;;
        old-profile) printf '  5 functions analyzed (out of 76): 6%% coverage.\n' ;;
        huffman-profile) printf '  16 functions analyzed (out of 141): 11%% coverage.\n' ;;
        wrong-functions) printf '  15 functions analyzed (out of 95): 15%% coverage.\n' ;;
        *) printf '  16 functions analyzed (out of 95): 16%% coverage.\n' ;;
    esac
    if [ "$FRAMA_BOUNDS_CASE" = conflicting-functions ]; then printf '  15 functions analyzed (out of 95): 15%% coverage.\n'; fi
    case "$FRAMA_BOUNDS_CASE" in
        missing-coverage) ;;
        old-profile) printf '  In these functions, 138 statements reached (out of 358): 38%% coverage.\n' ;;
        zero-coverage) printf '  In these functions, 0 statements reached (out of 983): 0%% coverage.\n' ;;
        wrong-coverage) printf '  In these functions, 557 statements reached (out of 983): 56%% coverage.\n' ;;
        *) printf '  In these functions, 558 statements reached (out of 983): 56%% coverage.\n' ;;
    esac
    if [ "$FRAMA_BOUNDS_CASE" = conflicting-coverage ]; then printf '  In these functions, 557 statements reached (out of 983): 56%% coverage.\n'; fi
    printf '  No errors or warnings raised during the analysis.\n'
    if [ "$FRAMA_BOUNDS_CASE" = duplicate-clean ]; then printf '  No errors or warnings raised during the analysis.\n'; fi
    if [ "$FRAMA_BOUNDS_CASE" = warning-summary ]; then
        printf '  Some errors and warnings have been raised during the analysis:\n'
        printf '    by the Frama-C kernel: 0 errors 1 warning\n'
    fi
    case "$FRAMA_BOUNDS_CASE" in alarm) printf '  1 alarms generated by the analysis.\n' ;; *) printf '  0 alarms generated by the analysis.\n' ;; esac
    if [ "$FRAMA_BOUNDS_CASE" = conflicting-alarms ]; then printf '  1 alarms generated by the analysis.\n'; fi
    case "$FRAMA_BOUNDS_CASE" in
        missing-assertions) ;;
        wrong-assertions) printf '  Assertions 1 valid 0 unknown 0 invalid 1 total\n' ;;
        *) printf '  Assertions 0 valid 0 unknown 0 invalid 0 total\n' ;;
    esac
    if [ "$FRAMA_BOUNDS_CASE" = duplicate-assertions ]; then printf '  Assertions 0 valid 0 unknown 0 invalid 0 total\n'; fi
    case "$FRAMA_BOUNDS_CASE" in
        missing-preconditions) ;;
        unknown) printf '  Preconditions 62 valid 1 unknown 0 invalid 63 total\n' ;;
        invalid) printf '  Preconditions 62 valid 0 unknown 1 invalid 63 total\n' ;;
        wrong-preconditions) printf '  Preconditions 62 valid 0 unknown 0 invalid 62 total\n' ;;
        old-profile) printf '  Preconditions 20 valid 0 unknown 0 invalid 20 total\n' ;;
        *) printf '  Preconditions 63 valid 0 unknown 0 invalid 63 total\n' ;;
    esac
    if [ "$FRAMA_BOUNDS_CASE" = conflicting-preconditions ]; then printf '  Preconditions 62 valid 0 unknown 0 invalid 62 total\n'; fi
    if [ "$FRAMA_BOUNDS_CASE" = status ]; then printf 'synthetic analyzer process failure\n' >&2; exit 23; fi
    exit 0
fi

check_marker() {
    marker_status=0
    grep -Fq "$3" "$4" || marker_status=$?
    case "$marker_status" in
        0|1) ;;
        *) printf 'FAIL: synthetic %s case marker scanner failed with status %s\n' "$1" "$marker_status" >&2; return 1 ;;
    esac
    if [ "$marker_status" -ne "$2" ]; then
        printf 'FAIL: synthetic %s case marker scan returned %s, expected %s\n' "$1" "$marker_status" "$2" >&2
        return 1
    fi
}

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
self="$repo_root/tests/test_frama_ans_decode_bounds_wrapper.sh"
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-frama-wrapper.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
ln -s "$self" "$test_tmp/frama-bounds-fixture"
mkdir "$test_tmp/scanner"
ln -s "$self" "$test_tmp/scanner/grep"

cases='clean unsupported-acsl-info empty incomplete version missing status alarm unknown invalid
warning uppercase-warning mixed-case-warning external-warning lowercase-error uppercase-error
mixed-case-failure timeout uppercase-timeout timed-out warning-summary pruned-body nonreturning-body
old-profile huffman-profile missing-all-witnesses reordered-witnesses unknown-witness bare-witness
nonsingleton-witness suffix-witness duplicate-summary duplicate-clean missing-functions wrong-functions
conflicting-functions missing-coverage wrong-coverage zero-coverage conflicting-coverage
missing-assertions wrong-assertions duplicate-assertions missing-preconditions wrong-preconditions
conflicting-preconditions conflicting-alarms scanner-error scanner-missing'
for number in 1 2 3 4 5 6; do
    cases="$cases missing-witness-$number wrong-witness-$number duplicate-witness-$number"
done
for function in vva_decode4_impl vva_decode_sequences_impl vva_decode_sequences vva_decode_sequences_v2 check_match_tail build_dec_direct read_hdr_v2 ans_br_init ans_br_fill ans_br_read ans_br_take ll_decode of_decode; do
    cases="$cases spec-$function"
done
total=0 failed=0
for test_case in $cases; do
    total=$((total + 1))
    analyzer="$test_tmp/frama-bounds-fixture"
    expected=1
    case "$test_case" in clean|unsupported-acsl-info) expected=0 ;; status) expected=23 ;; missing) analyzer="$test_tmp/no-analyzer"; expected=127 ;; esac
    scan_path=$PATH
    case "$test_case" in scanner-error|scanner-missing) scan_path="$test_tmp/scanner:$PATH" ;; esac
    actual=0
    PATH="$scan_path" FRAMA_C="$analyzer" FRAMA_BOUNDS_CASE="$test_case" \
        sh "$repo_root/tests/test_frama_ans_decode_bounds.sh" >"$test_tmp/$test_case.log" 2>&1 || actual=$?
    if [ "$actual" -ne "$expected" ]; then
        cat "$test_tmp/$test_case.log" >&2
        printf 'FAIL: synthetic %s case returned %s, expected %s\n' "$test_case" "$actual" "$expected" >&2
        failed=$((failed + 1))
        continue
    fi
    marker_expected=1
    case "$test_case" in clean|unsupported-acsl-info) marker_expected=0 ;; esac
    if ! check_marker "$test_case" "$marker_expected" 'PASS: Frama-C ANS bounds metadata and exact tails (production scalar scope)' "$test_tmp/$test_case.log"; then
        failed=$((failed + 1))
        continue
    fi
    printf 'PASS: synthetic formal-gate %s case\n' "$test_case"
done

ordinary_path=$PATH
ordinary_grep=$(command -v grep)
for scanner_case in scanner-error scanner-missing; do
    total=$((total + 1))
    case "$scanner_case" in scanner-error) scanner_status=2 ;; scanner-missing) scanner_status=127 ;; esac
    marker_log="$test_tmp/marker-$scanner_case.log"
    marker_result=0
    ( PATH="$test_tmp/scanner:$PATH" FRAMA_BOUNDS_CASE="$scanner_case" \
      check_marker "marker-$scanner_case" 1 'PASS: Frama-C ANS bounds' "$test_tmp/alarm.log"
    ) >"$marker_log" 2>&1 || marker_result=$?
    diagnostic_status=0
    grep -Fxq "FAIL: synthetic marker-$scanner_case case marker scanner failed with status $scanner_status" "$marker_log" || diagnostic_status=$?
    if [ "$marker_result" -ne 1 ] || [ "$diagnostic_status" -ne 0 ] || [ "$PATH" != "$ordinary_path" ] || [ "$(command -v grep)" != "$ordinary_grep" ]; then
        cat "$marker_log" >&2
        printf 'FAIL: synthetic marker-%s control did not reject scanner status %s or restore PATH\n' "$scanner_case" "$scanner_status" >&2
        failed=$((failed + 1))
        continue
    fi
    printf 'PASS: synthetic formal-gate marker-%s case\n' "$scanner_case"
done
printf 'RESULT: %s synthetic formal-gate cases, %s failures; this does not run or prove the codec\n' "$total" "$failed"
[ "$failed" -eq 0 ]
