#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Synthetic CLI fixtures test the quick suite's process and file boundaries.
set -Eeuo pipefail
export LC_ALL=C
umask 077

if [[ ${ZUPT_QUICK_HARNESS_CHILD:-0} == 1 ]]; then
    command=${1:-}
    shift
    case $command in
        compress)
            while (($# > 2)); do shift; done
            archive=$1
            source=$2
            printf '%s\n' "$source" >"$archive"
            if [[ $archive == */1.zupt && $ZUPT_QUICK_FAULT == compress-status ]]; then
                printf '%s\n' "$ZUPT_QUICK_FAULT" >>"$ZUPT_QUICK_EVENT_LOG"
                exit 7
            fi
            ;;
        extract)
            output=
            wrong=0
            archive=
            while (($#)); do
                case $1 in
                    -o) output=$2; shift 2 ;;
                    -p) [[ $2 != WRONG ]] || wrong=1; shift 2 ;;
                    --pq) shift 2 ;;
                    *) archive=$1; shift ;;
                esac
            done
            if ((wrong)); then
                if [[ $ZUPT_QUICK_FAULT == wrong-password-status ]]; then
                    printf '%s\n' "$ZUPT_QUICK_FAULT" >>"$ZUPT_QUICK_EVENT_LOG"
                    exit 2
                fi
                exit 1
            fi
            IFS= read -r source <"$archive"
            mkdir -p "$output/d"
            cp -- "$source/a.txt" "$source/b.bin" "$source/e.txt" "$output/d/"
            if [[ $archive == */1.zupt && $ZUPT_QUICK_FAULT != clean ]]; then
                case $ZUPT_QUICK_FAULT in
                    extract-status)
                        printf '%s\n' "$ZUPT_QUICK_FAULT" >>"$ZUPT_QUICK_EVENT_LOG"
                        exit 7 ;;
                    random-corrupt) printf 'corrupt\n' >"$output/d/b.bin" ;;
                    random-omit) rm -- "$output/d/b.bin" ;;
                    empty-omit) rm -- "$output/d/e.txt" ;;
                    *) exit 0 ;;
                esac
                printf '%s\n' "$ZUPT_QUICK_FAULT" >>"$ZUPT_QUICK_EVENT_LOG"
            fi
            ;;
        keygen)
            while (($#)); do
                if [[ $1 == -o ]]; then
                    printf 'fixture key\n' >"$2"
                    if [[ $2 == */k.key && $ZUPT_QUICK_FAULT == keygen-status ]]; then
                        printf '%s\n' "$ZUPT_QUICK_FAULT" >>"$ZUPT_QUICK_EVENT_LOG"
                        exit 7
                    fi
                    shift 2
                else shift
                fi
            done
            ;;
        test)
            printf 'Test: 3 passed, 0 failed (3 files)\n'
            if [[ $ZUPT_QUICK_FAULT == integrity-status ]]; then
                printf '%s\n' "$ZUPT_QUICK_FAULT" >>"$ZUPT_QUICK_EVENT_LOG"
                exit 7
            fi
            ;;
        help)
            for verb in compress extract list test info keygen version help disk bench verify; do
                printf '  zupt %s\n' "$verb"
            done
            if [[ $ZUPT_QUICK_FAULT == help-status ]]; then
                printf '%s\n' "$ZUPT_QUICK_FAULT" >>"$ZUPT_QUICK_EVENT_LOG"
                exit 7
            fi
            ;;
        *) printf 'unknown synthetic command: %s\n' "$command" >&2; exit 125 ;;
    esac
    exit 0
fi

root=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}
[[ -f $root/tests/run_quick.sh ]] || { printf 'FAIL: quick suite not found\n' >&2; exit 1; }
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-quick-harness.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cp -- "${BASH_SOURCE[0]}" "$work/cli"
cp -- "${BASH_SOURCE[0]}" "$work/cli with spaces"
chmod 700 "$work/cli" "$work/cli with spaces"
export ZUPT_QUICK_HARNESS_CHILD=1
failures=0
checks=0

run_case() {
    local mode=$1 cli=$2 expected=$3 status log
    log=$work/check-$checks.log
    export ZUPT_QUICK_FAULT=$mode ZUPT_QUICK_EVENT_LOG=$work/check-$checks.events
    if sh "$root/tests/run_quick.sh" "$cli" >"$log" 2>&1; then status=0
    else status=$?
    fi
    checks=$((checks + 1))
    if [[ $status != "$expected" ]] ||
       { [[ $mode != clean ]] && ! grep -Fxq "$mode" "$ZUPT_QUICK_EVENT_LOG"; }; then
        printf 'FAIL: quick boundary %s, expected %s, got %s\n' "$mode" "$expected" "$status" >&2
        cat -- "$log"
        failures=$((failures + 1))
    else
        printf 'PASS: quick boundary %s (%s)\n' "$mode" "${cli##*/}"
    fi
}

run_case clean "$work/cli" 0
run_case clean "$work/cli with spaces" 0
for mode in compress-status extract-status random-corrupt random-omit empty-omit integrity-status keygen-status help-status wrong-password-status; do
    run_case "$mode" "$work/cli" 1
done
if ((failures)); then
    printf 'FAIL: quick harness: %s/%s checks failed\n' "$failures" "$checks" >&2
    exit 1
fi
printf 'PASS: quick harness: %s checks\n' "$checks"
