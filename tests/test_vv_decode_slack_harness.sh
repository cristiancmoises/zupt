#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Exercise the real slack test's process supervision, not codec correctness.
set -Eeuo pipefail
export LC_ALL=C
umask 077

if [[ ${ZUPT_SLACK_CLEANUP_FAULT:-0} == 1 ]]; then
    cleanup_tool=${0##*/}
    case $cleanup_tool in
        find)
            [[ $# == 4 && $1 == "$ZUPT_SLACK_CLEANUP_PATH" &&
               $2 == -mindepth && $3 == 1 && $4 == -print ]] || exit 125 ;;
        rmdir)
            [[ $# == 2 && $1 == -- && $2 == "$ZUPT_SLACK_CLEANUP_PATH" ]] || exit 125 ;;
        *) exit 125 ;;
    esac
    printf 'SLACK-CLEANUP-TOOL-FAULT: %s\n' "$cleanup_tool" >&2
    exit 73
fi

if [[ ${ZUPT_SLACK_CHILD:-0} == 1 ]]; then
    command=${1:-}
    shift
    threads=ST
    case $command in
        c)
            [[ $# == 6 ]] || {
                printf 'slack compressor requires explicit thread selection\n' >&2
                exit 125
            }
            [[ $1 == -l ]] || exit 125
            level=$2
            shift 2
            [[ $1 == -t ]] || exit 125
            case $2 in
                1) threads=ST ;;
                4) threads=MT ;;
                *) exit 125 ;;
            esac
            shift 2
            [[ $# == 2 && -f $2 ]] || exit 125
            key=$threads$level
            archive=$1
            source=$2
            printf 'C %s\n' "$key" >>"$ZUPT_SLACK_TRACE"
            if [[ $ZUPT_SLACK_MODE == stale && $key == "$ZUPT_SLACK_TARGET" ]]; then
                IFS= read -r previous <"$ZUPT_SLACK_PREVIOUS"
                [[ -s $previous ]] || exit 125
            else
                printf '%s\n%s\n' "$source" "$key" >"$archive"
                printf '%s\n' "$archive" >"$ZUPT_SLACK_PREVIOUS"
            fi
            ;;
        x)
            [[ $# == 5 ]] || {
                printf 'slack extractor requires explicit thread selection\n' >&2
                exit 125
            }
            [[ $1 == -t ]] || exit 125
            case $2 in
                1) threads=ST ;;
                4) threads=MT ;;
                *) exit 125 ;;
            esac
            shift 2
            [[ $# == 3 && $1 == -o && -s $3 && -d $2 ]] || exit 125
            output=$2
            archive=$3
            {
                IFS= read -r source
                IFS= read -r key
            } <"$archive"
            [[ $key == "$threads"* && -f $source ]] || exit 125
            printf 'X %s\n' "$key" >>"$ZUPT_SLACK_TRACE"
            cp -- "$source" "$output/redundant.dat"
            ;;
        *) exit 125 ;;
    esac
    if [[ $key == "$ZUPT_SLACK_TARGET" ]]; then
        case $ZUPT_SLACK_MODE:$command in
            compress:c|stale:c|extract:x)
                printf '%s %s\n' "$ZUPT_SLACK_MODE" "$key" >>"$ZUPT_SLACK_EVENTS"
                printf 'SLACK-INJECTED-FAILURE %s %s\n' "$ZUPT_SLACK_MODE" "$key" >&2
                exit 73 ;;
            corrupt:x)
                printf 'corrupt\n' >"$output/redundant.dat"
                printf '%s %s\n' "$ZUPT_SLACK_MODE" "$key" >>"$ZUPT_SLACK_EVENTS" ;;
            omit:x)
                rm -- "$output/redundant.dat"
                printf '%s %s\n' "$ZUPT_SLACK_MODE" "$key" >>"$ZUPT_SLACK_EVENTS" ;;
        esac
    fi
    exit 0
fi

finish_tmpdir() {
    # The caller is finished; successful removal also establishes emptiness.
    rmdir -- "$1"
}

root=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}
[[ -f $root/tests/test_vv_decode_slack.sh ]] || exit 2
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-slack-harness.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cp -- "${BASH_SOURCE[0]}" "$work/cli"
cp -- "${BASH_SOURCE[0]}" "$work/cli with spaces"
chmod 700 "$work/cli" "$work/cli with spaces"
export ZUPT_SLACK_CHILD=1
checks=0
failures=0

run_case() {
    local mode=$1 target=$2 cli=$3 expected=$4 status bad=0 case_dir log label
    case $target in
        none) label=none ;;
        ST1) label=L1 ;;
        ST5) label=L5 ;;
        MT1) label='L1 (MT)' ;;
        MT9) label='L9 (MT)' ;;
        *) return 2 ;;
    esac
    case_dir=$work/case-$checks
    mkdir -p "$case_dir/tmp"
    log=$case_dir/raw.log
    export ZUPT_SLACK_MODE=$mode ZUPT_SLACK_TARGET=$target
    export ZUPT_SLACK_TRACE=$case_dir/trace ZUPT_SLACK_EVENTS=$case_dir/events
    export ZUPT_SLACK_PREVIOUS=$case_dir/previous
    : >"$ZUPT_SLACK_TRACE"
    : >"$ZUPT_SLACK_EVENTS"
    if (cd -- "$root" && TMPDIR=$case_dir/tmp bash tests/test_vv_decode_slack.sh "$cli") >"$log" 2>&1; then
        status=0
    else
        status=$?
    fi
    checks=$((checks + 1))
    [[ $status == "$expected" ]] || bad=1
    if [[ $mode == clean ]]; then
        printf 'C ST1\nX ST1\nC ST5\nX ST5\nC ST9\nX ST9\nC MT1\nX MT1\nC MT9\nX MT9\n' >"$case_dir/expected-trace"
        cmp -s "$case_dir/expected-trace" "$ZUPT_SLACK_TRACE" || bad=1
        grep -Fq '7 passed, 0 failed' "$log" || bad=1
        [[ ! -s $ZUPT_SLACK_EVENTS ]] || bad=1
    else
        printf '%s %s\n' "$mode" "$target" >"$case_dir/expected-event"
        cmp -s "$case_dir/expected-event" "$ZUPT_SLACK_EVENTS" || bad=1
        if grep -Fq '7 passed, 0 failed' "$log"; then bad=1; fi
        case $mode in
            compress|stale)
                grep -Fxq "C $target" "$ZUPT_SLACK_TRACE" || bad=1
                if grep -Fxq "X $target" "$ZUPT_SLACK_TRACE"; then bad=1; fi
                grep -Fq "degenerate-input $label compression failed (status 73)" "$log" || bad=1
                ;;
            extract)
                grep -Fxq "X $target" "$ZUPT_SLACK_TRACE" || bad=1
                grep -Fq "degenerate-input $label extraction failed (status 73)" "$log" || bad=1 ;;
            corrupt|omit)
                grep -Fxq "X $target" "$ZUPT_SLACK_TRACE" || bad=1
                grep -Fq "degenerate-input $label round-trip mismatch" "$log" || bad=1 ;;
        esac
        case $mode in
            compress|extract|stale)
                grep -Fq "SLACK-INJECTED-FAILURE $mode $target" "$log" || bad=1 ;;
        esac
    fi
    if ! finish_tmpdir "$case_dir/tmp"; then bad=1; fi
    if ((bad)); then
        printf 'FAIL: slack supervisor %s %s expected=%s actual=%s\n' "$mode" "$target" "$expected" "$status" >&2
        cat -- "$log" >&2
        cat -- "$ZUPT_SLACK_TRACE" >&2
        failures=$((failures + 1))
    else
        printf 'PASS: slack supervisor %s %s (%s)\n' "$mode" "$target" "${cli##*/}"
    fi
}

run_case clean none "$work/cli" 0
run_case clean none "$work/cli with spaces" 0
for target in ST1 MT1; do
    run_case compress "$target" "$work/cli" 1
    run_case extract "$target" "$work/cli" 1
done
run_case stale ST5 "$work/cli" 1
run_case stale MT9 "$work/cli" 1
run_case corrupt ST1 "$work/cli" 1
run_case omit MT1 "$work/cli" 1

cleanup_passed=0
mkdir "$work/cleanup-empty" "$work/cleanup-hidden" "$work/cleanup-failure" "$work/cleanup-tools"
printf 'retained cleanup sentinel\n' >"$work/cleanup-sentinel"
cp -- "$work/cleanup-sentinel" "$work/cleanup-hidden/.sentinel"
for cleanup_tool in find rmdir; do
    cp -- "${BASH_SOURCE[0]}" "$work/cleanup-tools/$cleanup_tool"
    chmod 700 "$work/cleanup-tools/$cleanup_tool"
done

if finish_tmpdir "$work/cleanup-empty" >"$work/cleanup-empty.out" 2>"$work/cleanup-empty.log"; then
    cleanup_status=0
else
    cleanup_status=$?
fi
printf 'CASE cleanup empty: status %s\n' "$cleanup_status"
cat -- "$work/cleanup-empty.out" "$work/cleanup-empty.log"
if [[ $cleanup_status == 0 ]]; then
    cleanup_passed=$((cleanup_passed + 1))
    printf 'PASS: slack cleanup accepts an empty directory\n'
else
    printf 'FAIL: slack cleanup rejected an empty directory\n' >&2
fi

if finish_tmpdir "$work/cleanup-hidden" >"$work/cleanup-hidden.out" 2>"$work/cleanup-hidden.log"; then
    cleanup_status=0
else
    cleanup_status=$?
fi
printf 'CASE cleanup hidden file: status %s\n' "$cleanup_status"
cat -- "$work/cleanup-hidden.out" "$work/cleanup-hidden.log"
if [[ $cleanup_status != 0 ]] && cmp -s -- "$work/cleanup-sentinel" "$work/cleanup-hidden/.sentinel"; then
    cleanup_passed=$((cleanup_passed + 1))
    printf 'PASS: slack cleanup rejects a nonempty directory and preserves its hidden file\n'
else
    printf 'FAIL: slack cleanup accepted or changed a nonempty directory\n' >&2
fi

if (
    export PATH="$work/cleanup-tools:$PATH"
    export ZUPT_SLACK_CLEANUP_FAULT=1 ZUPT_SLACK_CLEANUP_PATH=$work/cleanup-failure
    finish_tmpdir "$ZUPT_SLACK_CLEANUP_PATH"
) >"$work/cleanup-failure.out" 2>"$work/cleanup-failure.log"; then
    cleanup_status=0
else
    cleanup_status=$?
fi
printf 'CASE cleanup tool failure: status %s (expected 73)\n' "$cleanup_status"
cat -- "$work/cleanup-failure.out" "$work/cleanup-failure.log"
if [[ $cleanup_status == 73 && ! -s $work/cleanup-failure.out ]] &&
   grep -Eq '^SLACK-CLEANUP-TOOL-FAULT: (find|rmdir)$' "$work/cleanup-failure.log"; then
    cleanup_passed=$((cleanup_passed + 1))
    printf 'PASS: slack cleanup propagates the tool error and diagnostic\n'
else
    printf 'FAIL: slack cleanup hid a tool error or diagnostic\n' >&2
fi

if ((failures)); then
    printf 'FAIL: slack supervisor: %s/%s cases failed\n' "$failures" "$checks" >&2
    exit 1
fi
if ((cleanup_passed != 3)); then
    printf 'FAIL: slack cleanup: %s/3 checks passed\n' "$cleanup_passed" >&2
    exit 1
fi
printf 'PASS: slack cleanup: 3 checks\n'
printf 'PASS: slack supervisor: %s synthetic cases; real codec checks run separately\n' "$checks"
