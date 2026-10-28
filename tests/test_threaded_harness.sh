#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Process-boundary controls, not codec, encryption or throughput validation.
set -Eeuo pipefail
export LC_ALL=C
umask 077
ulimit -c 0

if [[ ${ZUPT_MT_TOOL_CHILD:-0} == 1 && ${0##*/} == python3 ]]; then
    if [[ ${ZUPT_MT_FIXTURE:-} == binary-* && $# == 6 &&
          $1 == -I && $2 == -B && $3 == -c &&
          $5 == */data/large_rand.bin && $6 == */data/sparse.bin ]]; then
        printf 'tool-binary-validator\n' >>"$ZUPT_MT_EVENT_LOG"
        if [[ $ZUPT_MT_FIXTURE == binary-validator-error ]]; then
            printf 'tool-binary-fault-%s\n' "$ZUPT_MT_FIXTURE" >>"$ZUPT_MT_EVENT_LOG"
            printf 'binary fixture sizes verified\n'
            exit 73
        fi
    fi
    if [[ -n ${ZUPT_MT_FIXTURE:-} && $# == 2 && $1 == -c &&
          $2 == *'import json, random; random.seed(42)'* ]]; then
        printf 'tool-generator-%s\n' "$ZUPT_MT_FIXTURE" >>"$ZUPT_MT_EVENT_LOG"
        case $ZUPT_MT_FIXTURE in
            json-exit) "$ZUPT_MT_REAL_PYTHON" "$@"; exit 73 ;;
            json-empty) exit 0 ;;
            json-short) printf '{"id":0,"name":"user_0","score":75.0}\n'; exit 0 ;;
            json-malformed) printf '{broken\n'; exit 0 ;;
            json-schema|json-nonfinite|json-long)
                exec "$ZUPT_MT_REAL_PYTHON" -I -B -c '
import json, sys
mode = sys.argv[1]
for index in range(5001 if mode == "json-long" else 5000):
    name = "invalid" if mode == "json-schema" and index == 2500 else f"user_{index}"
    score = float("nan") if mode == "json-nonfinite" else 75.0
    print(json.dumps({"id": index, "name": name, "score": score}))
' "$ZUPT_MT_FIXTURE"
                ;;
        esac
    fi
    if [[ ${ZUPT_MT_FIXTURE:-} == json-validator-error && $# == 5 &&
          $1 == -I && $2 == -B && $3 == -c && $5 == */data/data.json ]]; then
        printf 'tool-validator-error\n' >>"$ZUPT_MT_EVENT_LOG"
        printf 'validated 5000 fixture records\n'
        exit 73
    fi
    exec "$ZUPT_MT_REAL_PYTHON" "$@"
fi

if [[ ${ZUPT_MT_TOOL_CHILD:-0} == 1 && ${0##*/} == dd ]]; then
    kind= blocks=
    if [[ $# == 4 && $1 == if=/dev/urandom && $2 == bs=1024 &&
          $3 == count=500 && $4 == of=*/data/large_rand.bin ]]; then
        kind=random; blocks=500
    elif [[ $# == 4 && $1 == if=/dev/zero && $2 == bs=1024 &&
            $3 == count=200 && $4 == of=*/data/sparse.bin ]]; then
        kind=zero; blocks=200
    fi
    if [[ -n $kind && ${ZUPT_MT_FIXTURE:-} == binary-* ]]; then
        printf 'tool-binary-%s\n' "$kind" >>"$ZUPT_MT_EVENT_LOG"
        case $ZUPT_MT_FIXTURE in
            "binary-$kind-exit")
                "$ZUPT_MT_REAL_DD" "$@" || exit 125
                printf 'tool-binary-fault-%s\n' "$ZUPT_MT_FIXTURE" >>"$ZUPT_MT_EVENT_LOG"
                printf 'synthetic %s producer failure after complete output\n' "$kind" >&2
                exit 73
                ;;
            "binary-$kind-empty")
                : >"${4#of=}" || exit 125
                printf 'tool-binary-fault-%s\n' "$ZUPT_MT_FIXTURE" >>"$ZUPT_MT_EVENT_LOG"
                exit 0
                ;;
            "binary-$kind-short"|"binary-$kind-long")
                if [[ $ZUPT_MT_FIXTURE == *-short ]]; then blocks=$((blocks - 1))
                else blocks=$((blocks + 1))
                fi
                "$ZUPT_MT_REAL_DD" "$1" "$2" "count=$blocks" "$4" || exit 125
                printf 'tool-binary-fault-%s\n' "$ZUPT_MT_FIXTURE" >>"$ZUPT_MT_EVENT_LOG"
                exit 0
                ;;
        esac
    fi
    exec "$ZUPT_MT_REAL_DD" "$@"
fi

if [[ ${ZUPT_MT_TOOL_CHILD:-0} == 1 && ${0##*/} == mktemp ]]; then
    if [[ ${ZUPT_MT_LIFECYCLE:-} == mktemp-error ]]; then
        printf 'tool-mktemp-error\n' >>"$ZUPT_MT_EVENT_LOG"
        exit 73
    fi
    exec "$ZUPT_MT_REAL_MKTEMP" "$@"
fi

if [[ ${ZUPT_MT_TOOL_CHILD:-0} == 1 && ${0##*/} == grep ]]; then
    last_argument=
    for argument in "$@"; do last_argument=$argument; done
    if [[ $last_argument == */t9-error.log ]]; then
        if [[ $ZUPT_MT_FAULT == grep-scan && $* == *AddressSanitizer* ]] ||
           [[ $ZUPT_MT_FAULT == grep-auth && $* == *'Error: Authentication failed'* ]]; then
            printf 'tool-%s\n' "$ZUPT_MT_FAULT" >>"$ZUPT_MT_EVENT_LOG"
            printf 'Error: Authentication failed (synthetic tool output)\n'
            exit 73
        fi
    fi
    if [[ $last_argument == */t10-result.log ]]; then
        if [[ $ZUPT_MT_FAULT == test-grep-scan && $* == *AddressSanitizer* ]] ||
           [[ $ZUPT_MT_FAULT == test-grep-summary && $* == *'  Test: 9 passed, 0 failed (9 files)'* ]] ||
           [[ $ZUPT_MT_FAULT == test-grep-count && $* == *'-acF'* && $* == *'Test:'* ]]; then
            printf 'tool-%s\n' "$ZUPT_MT_FAULT" >>"$ZUPT_MT_EVENT_LOG"
            if [[ $ZUPT_MT_FAULT == test-grep-count ]]; then
                printf '1\n'
            else
                printf '  Test: 9 passed, 0 failed (9 files)\n'
            fi
            exit 73
        fi
    fi
    exec "$ZUPT_MT_REAL_GREP" "$@"
fi

if [[ ${ZUPT_MT_HARNESS_CHILD:-0} == 1 ]]; then
    command=${1:-}
    shift
    if [[ -n ${ZUPT_MT_FIXTURE:-} ]]; then
        printf 'cli-%s\n' "$command" >>"$ZUPT_MT_EVENT_LOG"
    fi
    case $command in
        version)
            if [[ -n ${ZUPT_MT_LIFECYCLE:-} ]]; then
                printf 'version\n' >>"$ZUPT_MT_EVENT_LOG"
                case $ZUPT_MT_LIFECYCLE in
                    normal|HUP|INT|TERM)
                        candidates=("$TMPDIR"/zupt_mt_*)
                        observed=/tmp/zupt_mt_$ZUPT_MT_SUITE_PID
                        if [[ ${#candidates[@]} == 1 && -d ${candidates[0]} ]]; then
                            observed=${candidates[0]}
                        fi
                        [[ -d $observed ]] || {
                            printf 'SETUP-FAILURE: no workspace at version checkpoint\n' >>"$ZUPT_MT_EVENT_LOG"
                            exit 125
                        }
                        printf '%s\n' "$observed" >"$ZUPT_MT_RECORD"
                        stat -Lc '%a' -- "$observed" >>"$ZUPT_MT_RECORD"
                        if [[ -L $observed ]]; then printf 'symlink\n'
                        else printf 'directory\n'
                        fi >>"$ZUPT_MT_RECORD"
                        if [[ $ZUPT_MT_LIFECYCLE != normal ]]; then
                            kill -s "$ZUPT_MT_LIFECYCLE" "$ZUPT_MT_SUITE_PID" || {
                                printf 'SETUP-FAILURE: cannot signal suite\n' >>"$ZUPT_MT_EVENT_LOG"
                                exit 125
                            }
                            printf 'signal-%s\n' "$ZUPT_MT_LIFECYCLE" >>"$ZUPT_MT_EVENT_LOG"
                        fi
                        ;;
                esac
            fi
            if [[ -n ${ZUPT_MT_FIXTURE:-} ]]; then
                candidates=("$TMPDIR"/zupt_mt_*)
                if [[ ${#candidates[@]} != 1 || ! -d ${candidates[0]} || -L ${candidates[0]} ]]; then
                    printf 'SETUP-FAILURE: no private JSON workspace\n' >>"$ZUPT_MT_EVENT_LOG"
                    exit 125
                fi
                printf '%s\n' "${candidates[0]}" >"$ZUPT_MT_RECORD"
            fi
            printf 'zupt threaded process fixture\n'
            ;;
        compress)
            threads=
            while (($#)); do
                case $1 in
                    -t) threads=$2; shift 2 ;;
                    -l|-p) shift 2 ;;
                    -s|-f|--solid) shift ;;
                    *) break ;;
                esac
            done
            archive=$1
            shift
            many_compress=0
            if [[ ${ZUPT_MT_FIXTURE:-} == many-* && $archive == */t6.zupt ]]; then
                [[ $threads == 8 && $# == 1 && $1 == */many/ ]] || {
                    printf 'SETUP-FAILURE: unexpected many-file compression arguments\n' >>"$ZUPT_MT_EVENT_LOG"
                    exit 125
                }
                many_compress=1
                printf 'many-call-compress threads=8\n' >>"$ZUPT_MT_EVENT_LOG"
            fi
            timing_phase=
            if [[ ${ZUPT_MT_FIXTURE:-} == timing-* ]]; then
                case $archive in
                    */speed1.zupt) timing_phase=1 ;;
                    */speed4.zupt) timing_phase=4 ;;
                esac
                if [[ -n $timing_phase ]]; then
                    [[ $threads == "$timing_phase" && $# == 1 && $1 == */large_10m.txt ]] || {
                        printf 'SETUP-FAILURE: unexpected timing arguments\n' >>"$ZUPT_MT_EVENT_LOG"
                        exit 125
                    }
                    printf 'timing-call-%s threads=%s\n' "$timing_phase" "$threads" >>"$ZUPT_MT_EVENT_LOG"
                    case $ZUPT_MT_FIXTURE in
                        "timing-$timing_phase-"*)
                            printf 'timing-fault-%s\n' "$ZUPT_MT_FIXTURE" >>"$ZUPT_MT_EVENT_LOG"
                            printf 'timing stdout %s\n' "$ZUPT_MT_FIXTURE"
                            printf 'timing stderr %s\n' "$ZUPT_MT_FIXTURE" >&2
                            case $ZUPT_MT_FIXTURE in
                                *-before)
                                    [[ ! -e $archive ]] || exit 125
                                    printf 'timing-result-%s status=37 state=missing\n' "$timing_phase" >>"$ZUPT_MT_EVENT_LOG"
                                    exit 37 ;;
                                *-missing)
                                    [[ ! -e $archive ]] || exit 125
                                    printf 'timing-result-%s status=0 state=missing\n' "$timing_phase" >>"$ZUPT_MT_EVENT_LOG"
                                    exit 0 ;;
                                *-empty)
                                    : >"$archive"
                                    printf 'timing-result-%s status=0 state=empty\n' "$timing_phase" >>"$ZUPT_MT_EVENT_LOG"
                                    exit 0 ;;
                                *-directory)
                                    mkdir "$archive"
                                    printf x >"$archive/member"
                                    printf 'timing-result-%s status=0 state=directory\n' "$timing_phase" >>"$ZUPT_MT_EVENT_LOG"
                                    exit 0 ;;
                            esac
                            ;;
                    esac
                fi
            fi
            if [[ ${ZUPT_MT_LIFECYCLE:-} == normal && ! -e $ZUPT_MT_FILE_MODE ]]; then
                stat -c '%a' -- "${1%/}/single.bin" >"$ZUPT_MT_FILE_MODE"
            fi
            if [[ ${ZUPT_MT_FIXTURE:-} == json-clean && ! -e $ZUPT_MT_JSON_HASH ]]; then
                "$ZUPT_MT_REAL_PYTHON" -I -B -c '
import hashlib, json, math, sys
with open(sys.argv[1], "rb") as source:
    raw = source.read()
rows = [json.loads(line) for line in raw.splitlines()]
assert len(rows) == 5000
assert rows[0]["id"] == 0 and rows[0]["name"] == "user_0"
assert rows[-1]["id"] == 4999 and rows[-1]["name"] == "user_4999"
assert all(type(row["id"]) is int and row["id"] == index and
           row["name"] == f"user_{index}" for index, row in enumerate(rows))
assert all(type(row["score"]) is float and math.isfinite(row["score"]) for row in rows)
print(hashlib.sha256(raw).hexdigest())
' "${1%/}/data.json" >"$ZUPT_MT_JSON_HASH"
            fi
            if [[ ${ZUPT_MT_FIXTURE:-} == binary-clean && ! -e $ZUPT_MT_BINARY_SIZES ]]; then
                "$ZUPT_MT_REAL_PYTHON" -I -B -c '
from pathlib import Path
import sys
directory = Path(sys.argv[1])
random = directory / "large_rand.bin"
zero = directory / "sparse.bin"
if random.stat().st_size != 512000 or zero.stat().st_size != 204800:
    raise ValueError("normal binary fixture size mismatch")
if zero.read_bytes() != bytes(204800):
    raise ValueError("zero fixture contains nonzero data")
print("512000 204800")
' "${1%/}" >"$ZUPT_MT_BINARY_SIZES"
            fi
            printf '%s\n' "$@" >"$archive"
            if [[ $many_compress == 1 ]]; then
                [[ -f $archive && -s $archive ]] || exit 125
                if [[ $ZUPT_MT_FIXTURE == many-compress-after ]]; then
                    printf 'many-fault-%s\n' "$ZUPT_MT_FIXTURE" >>"$ZUPT_MT_EVENT_LOG"
                    printf 'many stdout %s\n' "$ZUPT_MT_FIXTURE"
                    printf 'many stderr %s\n' "$ZUPT_MT_FIXTURE" >&2
                    printf 'many-compress-result status=37 state=nonempty\n' >>"$ZUPT_MT_EVENT_LOG"
                    exit 37
                fi
                printf 'many-compress-result status=0 state=nonempty\n' >>"$ZUPT_MT_EVENT_LOG"
            fi
            if [[ -n $timing_phase ]]; then
                [[ -f $archive && -s $archive ]] || exit 125
                if [[ $ZUPT_MT_FIXTURE == "timing-$timing_phase-after" ]]; then
                    printf 'timing-result-%s status=37 state=nonempty\n' "$timing_phase" >>"$ZUPT_MT_EVENT_LOG"
                    exit 37
                fi
                printf 'timing-result-%s status=0 state=nonempty\n' "$timing_phase" >>"$ZUPT_MT_EVENT_LOG"
            fi
            ;;
        extract)
            output= archive= wrong=0
            while (($#)); do
                case $1 in
                    -o) output=$2; shift 2 ;;
                    -p) [[ $2 != WRONG ]] || wrong=1; shift 2 ;;
                    *) archive=$1; shift ;;
                esac
            done
            if ((wrong)); then
                fault=$ZUPT_MT_FAULT
                [[ $fault != test-* ]] || fault=clean
                printf '%s\n' "$fault" >>"$ZUPT_MT_EVENT_LOG"
                if [[ $fault == unrelated-1 ]]; then
                    printf 'unrelated execution failure\n' >&2
                    exit 1
                fi
                printf 'Error: Authentication failed (synthetic rejection)\n' >&2
                case $fault in
                    status-0|status-2|status-127) exit "${fault#status-}" ;;
                    term|segv)
                        signal=TERM
                        [[ $fault == term ]] || signal=SEGV
                        kill -s "$signal" "$$" || :
                        printf 'SETUP-FAILURE: %s fixture survived self-signal\n' "$signal" >>"$ZUPT_MT_EVENT_LOG"
                        exit 125
                        ;;
                    asan) printf 'ERROR: AddressSanitizer: synthetic diagnostic\n' >&2 ;;
                    lsan) printf 'ERROR: LeakSanitizer: synthetic diagnostic\n' >&2 ;;
                    ubsan) printf 'UndefinedBehaviorSanitizer: synthetic diagnostic\n' >&2 ;;
                    runtime) printf 'fixture.c:1:1: runtime error: synthetic diagnostic\n' >&2 ;;
                    binary-prefix) printf '\000ERROR: AddressSanitizer: synthetic diagnostic\n' >&2 ;;
                    clean|grep-scan|grep-auth) ;;
                    *) printf 'SETUP-FAILURE: unknown fault\n' >>"$ZUPT_MT_EVENT_LOG"; exit 125 ;;
                esac
                exit 1
            fi
            mkdir -p -- "$output"
            # Only generated private fixtures are linked. Avoid duplicating
            # large inputs for every extraction in each whole-script control.
            while IFS= read -r source; do
                if [[ $archive == */t6.zupt ]]; then
                    # Absolute inputs retain their path without the leading
                    # slash in real archives; mirror that T6 layout here.
                    prefix=${source%/}; prefix=${prefix%/*}; prefix=${prefix#/}
                    mkdir -p -- "$output/$prefix"
                    cp -al -- "${source%/}" "$output/$prefix/"
                else
                    cp -al -- "${source%/}" "$output/"
                fi
            done <"$archive"
            if [[ ${ZUPT_MT_FIXTURE:-} == many-* && $archive == */t6.zupt ]]; then
                [[ $output == "${archive%/*}/t6_out" ]] || exit 125
                printf 'many-call-extract\n' >>"$ZUPT_MT_EVENT_LOG"
                "$ZUPT_MT_REAL_PYTHON" -I -B -c '
import hashlib, pathlib, sys
mode, workspace, output = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
original = workspace / "many" / "file_2.txt"
target = output / str(workspace).lstrip("/") / "many" / "file_2.txt"
raw = original.read_bytes()
before = hashlib.sha256(raw).digest()
assert target.read_bytes() == raw and raw.startswith(b"File 2 content: ")
assert sum(path.is_file() for path in output.rglob("*")) == 1000
if mode == "many-corrupt":
    target.unlink()  # Break the fixture hard link before writing.
    target.write_bytes(b"X" + raw[1:])
    assert target.stat().st_size == len(raw) and target.read_bytes() != raw
elif mode == "many-rename":
    target.rename(target.with_name("file_1001.txt"))
elif mode == "many-relocate":
    target.parent.joinpath("nested").mkdir()
    target.rename(target.parent / "nested" / target.name)
elif mode == "many-missing":
    target.unlink()
elif mode == "many-extra":
    target.with_name("file_1001.txt").write_bytes(b"unexpected member\n")
assert hashlib.sha256(original.read_bytes()).digest() == before
count = sum(path.is_file() for path in output.rglob("*"))
print(f"many-extract-result files={count} source-preserved=1")
' "$ZUPT_MT_FIXTURE" "${archive%/*}" "$output" >>"$ZUPT_MT_EVENT_LOG" || {
                    printf 'SETUP-FAILURE: many-file mutation failed\n' >>"$ZUPT_MT_EVENT_LOG"
                    exit 125
                }
                case $ZUPT_MT_FIXTURE in
                    many-clean|many-compress-after) ;;
                    *)
                        printf 'many-fault-%s\n' "$ZUPT_MT_FIXTURE" >>"$ZUPT_MT_EVENT_LOG"
                        printf 'many stdout %s\n' "$ZUPT_MT_FIXTURE"
                        printf 'many stderr %s\n' "$ZUPT_MT_FIXTURE" >&2
                        ;;
                esac
                if [[ $ZUPT_MT_FIXTURE == many-extract-after ]]; then
                    printf 'many-extract-status=37\n' >>"$ZUPT_MT_EVENT_LOG"
                    exit 37
                fi
                printf 'many-extract-status=0\n' >>"$ZUPT_MT_EVENT_LOG"
            fi
            ;;
        test)
            if [[ $ZUPT_MT_FAULT == test-* ]]; then
                printf '%s\n' "$ZUPT_MT_FAULT" >>"$ZUPT_MT_EVENT_LOG"
            fi
            case $ZUPT_MT_FAULT in
                test-unrelated) printf 'unrelated operation: 0 failed attempts\n'; exit 0 ;;
                test-ten-failed) printf '  Test: 0 passed, 10 failed (10 files)\n'; exit 0 ;;
                test-wrong-count) printf '  Test: 8 passed, 0 failed (8 files)\n'; exit 0 ;;
                test-missing-summary) printf 'synthetic archive opened\n'; exit 0 ;;
            esac
            printf '  Test: 9 passed, 0 failed (9 files)\n'
            case $ZUPT_MT_FAULT in
                test-status-1|test-status-2|test-status-127) exit "${ZUPT_MT_FAULT#test-status-}" ;;
                test-term|test-segv)
                    signal=TERM
                    [[ $ZUPT_MT_FAULT == test-term ]] || signal=SEGV
                    kill -s "$signal" "$$" || :
                    printf 'SETUP-FAILURE: %s fixture survived self-signal\n' "$signal" >>"$ZUPT_MT_EVENT_LOG"
                    exit 125
                    ;;
                test-asan) printf 'ERROR: AddressSanitizer: synthetic diagnostic\n' >&2 ;;
                test-lsan) printf 'ERROR: LeakSanitizer: synthetic diagnostic\n' >&2 ;;
                test-ubsan) printf 'UndefinedBehaviorSanitizer: synthetic diagnostic\n' >&2 ;;
                test-runtime) printf 'fixture.c:1:1: runtime error: synthetic diagnostic\n' >&2 ;;
                test-binary-prefix) printf '\000ERROR: AddressSanitizer: synthetic diagnostic\n' >&2 ;;
                test-duplicate-summary) printf '  Test: 9 passed, 0 failed (9 files)\n' ;;
                test-conflicting-summary) printf '\tTest: 8 passed, 1 failed (9 files)\n' ;;
                test-binary-summary) printf '\000Test: 8 passed, 1 failed (9 files)\n' ;;
            esac
            ;;
        *) printf 'SETUP-FAILURE: unknown command\n' >>"$ZUPT_MT_EVENT_LOG"; exit 125 ;;
    esac
    exit 0
fi

root=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}
[[ -f $root/tests/test_threaded.sh ]] || { printf 'FAIL: threaded suite not found\n' >&2; exit 1; }
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-mt-harness.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cp -- "${BASH_SOURCE[0]}" "$work/cli"
chmod 700 "$work/cli"
mkdir "$work/tools"
cp -- "${BASH_SOURCE[0]}" "$work/tools/grep"
chmod 700 "$work/tools/grep"
cp -- "${BASH_SOURCE[0]}" "$work/tools/mktemp"
chmod 700 "$work/tools/mktemp"
cp -- "${BASH_SOURCE[0]}" "$work/tools/python3"
chmod 700 "$work/tools/python3"
cp -- "${BASH_SOURCE[0]}" "$work/tools/dd"
chmod 700 "$work/tools/dd"
export ZUPT_MT_REAL_GREP ZUPT_MT_REAL_MKTEMP ZUPT_MT_REAL_PYTHON ZUPT_MT_REAL_DD
ZUPT_MT_REAL_GREP=$(command -v grep)
ZUPT_MT_REAL_MKTEMP=$(command -v mktemp)
ZUPT_MT_REAL_PYTHON=$(command -v python3)
ZUPT_MT_REAL_DD=$(command -v dd)
export ZUPT_MT_HARNESS_CHILD=1
failures=0
checks=0

run_case() {
    local mode=$1 expected=$2 status log events summary case_path setup_status failure
    log=$work/$mode.log
    events=$work/$mode.events
    export ZUPT_MT_FAULT=$mode ZUPT_MT_EVENT_LOG=$events
    if [[ $mode == grep-* || $mode == test-grep-* ]]; then
        export ZUPT_MT_TOOL_CHILD=1
        case_path=$work/tools:$PATH
    else
        unset ZUPT_MT_TOOL_CHILD
        case_path=$PATH
    fi
    if PATH=$case_path sh "$root/tests/test_threaded.sh" "$work/cli" >"$log" 2>&1; then status=0
    else status=$?
    fi
    checks=$((checks + 1))
    if "$ZUPT_MT_REAL_GREP" -F 'SETUP-FAILURE:' "$events" >/dev/null; then setup_status=0
    else setup_status=$?
    fi
    summary='  MT RESULTS: 13 passed, 1 failed (14 tests)'
    [[ $expected != 0 ]] || summary='  MT RESULTS: 14 passed, 0 failed (14 tests)'
    failure='  FAIL: Wrong password'
    [[ $mode != test-* ]] || failure='  FAIL: Integrity test'
    if [[ $status != "$expected" ]] ||
       ! "$ZUPT_MT_REAL_GREP" -Fx -- "$mode" "$events" >/dev/null ||
       [[ $setup_status != 1 ]] ||
       ! "$ZUPT_MT_REAL_GREP" -Fx -- "$summary" "$log" >/dev/null ||
       { [[ $expected == 1 ]] && ! "$ZUPT_MT_REAL_GREP" -F -- "$failure" "$log" >/dev/null; } ||
       { [[ $mode == grep-* || $mode == test-grep-* ]] && ! "$ZUPT_MT_REAL_GREP" -Fx -- "tool-$mode" "$events" >/dev/null; }; then
        printf 'FAIL: threaded boundary %s: expected %s, got %s\n' "$mode" "$expected" "$status" >&2
        cat -- "$log"
        cat -- "$events"
        failures=$((failures + 1))
    else
        printf 'PASS: threaded boundary %s\n' "$mode"
    fi
}

run_case clean 0
for mode in status-0 status-2 status-127 unrelated-1 term segv asan lsan ubsan runtime binary-prefix grep-scan grep-auth; do
    run_case "$mode" 1
done
for mode in test-status-1 test-status-2 test-status-127 test-term test-segv test-asan test-lsan test-ubsan test-runtime test-binary-prefix test-unrelated test-ten-failed test-wrong-count test-missing-summary test-duplicate-summary test-conflicting-summary test-binary-summary test-grep-scan test-grep-summary test-grep-count; do
    run_case "$mode" 1
done

run_lifecycle() {
    local mode=$1 expected=$2 directory base status valid=1 pid= legacy= observed= permissions= kind=
    directory=$work/lifecycle-$mode
    base=$directory/tmp\ with\ spaces
    mkdir -p -- "$base" "$directory/sentinel/data"
    printf 'preserve this sentinel\n' >"$directory/sentinel/data/hello.txt"
    export ZUPT_MT_LIFECYCLE=$mode ZUPT_MT_FAULT=clean
    export ZUPT_MT_EVENT_LOG=$directory/events ZUPT_MT_RECORD=$directory/workspace
    export ZUPT_MT_FILE_MODE=$directory/file-mode
    export ZUPT_MT_PID_FILE=$directory/pid ZUPT_MT_SENTINEL=$directory/sentinel
    : >"$ZUPT_MT_EVENT_LOG"
    case $mode in
        bad-file) printf 'not a directory\n' >"$directory/not-directory"; base=$directory/not-directory ;;
        bad-missing) base=$directory/missing/parent ;;
    esac
    # exec preserves the PID used for the historical name. Atomic symlink
    # creation refuses an existing path instead of writing into a directory.
    # Reset signal dispositions before exec, including inherited ignored INT.
    if TMPDIR=$base PATH=$work/tools:$PATH ZUPT_MT_TOOL_CHILD=1 python3 -I -B -c '
import os, signal, sys
pid = os.getpid()
os.environ["ZUPT_MT_SUITE_PID"] = str(pid)
with open(os.environ["ZUPT_MT_PID_FILE"], "x") as receipt:
    receipt.write(str(pid) + "\n")
if os.environ["ZUPT_MT_LIFECYCLE"] == "normal":
    os.symlink(os.environ["ZUPT_MT_SENTINEL"], "/tmp/zupt_mt_" + str(pid))
os.umask(0)
for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(number, signal.SIG_DFL)
os.execvp("sh", ["sh", sys.argv[1], sys.argv[2]])
' "$root/tests/test_threaded.sh" "$work/cli" >"$directory/log" 2>&1; then status=0
    else status=$?
    fi
    checks=$((checks + 1))
    [[ $status == "$expected" ]] || valid=0
    if [[ -f $directory/pid ]]; then IFS= read -r pid <"$directory/pid"; fi
    [[ $pid =~ ^[0-9]+$ ]] || valid=0
    if "$ZUPT_MT_REAL_GREP" -F 'SETUP-FAILURE:' "$directory/events" >/dev/null; then valid=0
    elif [[ $? != 1 ]]; then valid=0
    fi
    case $mode in
        normal|HUP|INT|TERM)
            if [[ -f $directory/workspace ]]; then
                { IFS= read -r observed; IFS= read -r permissions; IFS= read -r kind; } <"$directory/workspace" || valid=0
            fi
            [[ $observed == "$base"/zupt_mt_* && $permissions == 700 && $kind == directory ]] || valid=0
            [[ -n $observed && ! -e $observed && ! -L $observed ]] || valid=0
            "$ZUPT_MT_REAL_GREP" -Fx version "$directory/events" >/dev/null || valid=0
            if [[ $mode == normal ]]; then
                legacy=/tmp/zupt_mt_$pid
                [[ -L $legacy && $(readlink -- "$legacy") == "$directory/sentinel" ]] || valid=0
                [[ $(cat -- "$directory/sentinel/data/hello.txt") == 'preserve this sentinel' ]] || valid=0
                [[ -f $directory/file-mode && $(cat -- "$directory/file-mode") == 600 ]] || valid=0
                "$ZUPT_MT_REAL_GREP" -Fx '  MT RESULTS: 14 passed, 0 failed (14 tests)' "$directory/log" >/dev/null || valid=0
                # Remove only the exact symlink this launcher created, after
                # checking the sentinel; never follow it for recursive cleanup.
                if [[ -L $legacy && $(readlink -- "$legacy") == "$directory/sentinel" ]]; then
                    rm -- "$legacy"
                fi
            else
                "$ZUPT_MT_REAL_GREP" -Fx "signal-$mode" "$directory/events" >/dev/null || valid=0
            fi
            ;;
        *)
            if "$ZUPT_MT_REAL_GREP" -Fx version "$directory/events" >/dev/null; then valid=0
            elif [[ $? != 1 ]]; then valid=0
            fi
            "$ZUPT_MT_REAL_GREP" -Fx 'Cannot create private threaded-test workspace' "$directory/log" >/dev/null || valid=0
            if [[ $mode == mktemp-error ]]; then
                "$ZUPT_MT_REAL_GREP" -Fx tool-mktemp-error "$directory/events" >/dev/null || valid=0
            fi
            ;;
    esac
    if [[ $valid == 1 ]]; then
        printf 'PASS: threaded lifecycle %s\n' "$mode"
        case $mode in
            normal|HUP|INT|TERM)
                printf 'LIFECYCLE_STATE %s status=%s mode=%s kind=%s cleaned=1\n' \
                    "$mode" "$status" "$permissions" "$kind"
                ;;
        esac
        [[ $mode != normal ]] || printf 'LIFECYCLE_FIXTURE_MODE=%s\n' "$(cat -- "$directory/file-mode")"
    else
        printf 'FAIL: threaded lifecycle %s: expected %s, got %s\n' "$mode" "$expected" "$status" >&2
        cat -- "$directory/log" "$directory/events"
        for record in workspace file-mode; do
            [[ ! -f $directory/$record ]] || cat -- "$directory/$record"
        done
        if [[ $mode == normal ]]; then
            printf 'Observed sentinel: '
            cat -- "$directory/sentinel/data/hello.txt"
        fi
        failures=$((failures + 1))
    fi
}

run_lifecycle normal 0
run_lifecycle HUP 129
run_lifecycle INT 130
run_lifecycle TERM 143
for mode in bad-file bad-missing mktemp-error; do run_lifecycle "$mode" 1; done

run_fixture() {
    local mode=$1 expected=$2 directory status valid=1 observed= scan hash= command
    directory=$work/fixture-$mode
    mkdir -p -- "$directory/tmp with spaces"
    unset ZUPT_MT_LIFECYCLE
    export ZUPT_MT_FIXTURE=$mode ZUPT_MT_FAULT=clean
    export ZUPT_MT_EVENT_LOG=$directory/events ZUPT_MT_RECORD=$directory/workspace
    export ZUPT_MT_JSON_HASH=$directory/json-hash
    : >"$ZUPT_MT_EVENT_LOG"
    if TMPDIR="$directory/tmp with spaces" PATH=$work/tools:$PATH ZUPT_MT_TOOL_CHILD=1 \
        sh "$root/tests/test_threaded.sh" "$work/cli" >"$directory/log" 2>&1; then status=0
    else status=$?
    fi
    checks=$((checks + 1))
    [[ $status == "$expected" ]] || valid=0
    [[ ! -f $directory/workspace ]] || IFS= read -r observed <"$directory/workspace"
    [[ $observed == "$directory/tmp with spaces"/zupt_mt_* && ! -e $observed && ! -L $observed ]] || valid=0
    "$ZUPT_MT_REAL_GREP" -Fx cli-version "$directory/events" >/dev/null || valid=0
    "$ZUPT_MT_REAL_GREP" -Fx "tool-generator-$mode" "$directory/events" >/dev/null || valid=0
    if "$ZUPT_MT_REAL_GREP" -F SETUP-FAILURE: "$directory/events" >/dev/null; then valid=0
    elif [[ $? != 1 ]]; then valid=0
    fi
    if [[ $expected == 0 ]]; then
        "$ZUPT_MT_REAL_GREP" -Fx '  MT RESULTS: 14 passed, 0 failed (14 tests)' "$directory/log" >/dev/null || valid=0
        for command in compress extract test; do
            "$ZUPT_MT_REAL_GREP" -Fx "cli-$command" "$directory/events" >/dev/null || valid=0
        done
        [[ ! -f $directory/json-hash ]] || IFS= read -r hash <"$directory/json-hash"
        [[ $hash =~ ^[0-9a-f]{64}$ ]] || valid=0
    else
        "$ZUPT_MT_REAL_GREP" -Fx 'Cannot prepare threaded-test JSON fixture' "$directory/log" >/dev/null || valid=0
        if "$ZUPT_MT_REAL_GREP" -E '^cli-(compress|extract|test)$' "$directory/events" >/dev/null; then scan=0
        else scan=$?
        fi
        [[ $scan == 1 ]] || valid=0
        if "$ZUPT_MT_REAL_GREP" -aE '── T1:|MT RESULTS:' "$directory/log" >/dev/null; then scan=0
        else scan=$?
        fi
        [[ $scan == 1 ]] || valid=0
        if [[ $mode == json-validator-error ]]; then
            "$ZUPT_MT_REAL_GREP" -Fx tool-validator-error "$directory/events" >/dev/null || valid=0
        fi
    fi
    if [[ $valid == 1 ]]; then
        printf 'PASS: threaded JSON fixture %s\n' "$mode"
        if [[ $expected == 0 ]]; then
            printf 'JSON_FIXTURE_SHA256=%s\n' "$hash"
        else
            printf 'JSON_FIXTURE_STATE %s status=%s cleaned=1 before-codec=1\n' "$mode" "$status"
        fi
    else
        printf 'FAIL: threaded JSON fixture %s: expected %s, got %s\n' "$mode" "$expected" "$status" >&2
        cat -- "$directory/log" "$directory/events"
        failures=$((failures + 1))
    fi
}

run_fixture json-clean 0
for mode in json-exit json-empty json-short json-malformed json-schema json-nonfinite json-long json-validator-error; do
    run_fixture "$mode" 1
done

run_binary_fixture() {
    local mode=$1 expected=$2 directory status valid=1 observed= scan sizes= command event
    directory=$work/fixture-$mode
    mkdir -p -- "$directory/tmp with spaces"
    unset ZUPT_MT_LIFECYCLE
    export ZUPT_MT_FIXTURE=$mode ZUPT_MT_FAULT=clean
    export ZUPT_MT_EVENT_LOG=$directory/events ZUPT_MT_RECORD=$directory/workspace
    export ZUPT_MT_BINARY_SIZES=$directory/binary-sizes
    : >"$ZUPT_MT_EVENT_LOG"
    if TMPDIR="$directory/tmp with spaces" PATH=$work/tools:$PATH ZUPT_MT_TOOL_CHILD=1 \
        sh "$root/tests/test_threaded.sh" "$work/cli" >"$directory/log" 2>&1; then status=0
    else status=$?
    fi
    checks=$((checks + 1))
    [[ $status == "$expected" ]] || valid=0
    [[ ! -f $directory/workspace ]] || IFS= read -r observed <"$directory/workspace"
    [[ $observed == "$directory/tmp with spaces"/zupt_mt_* && ! -e $observed && ! -L $observed ]] || valid=0
    for event in cli-version tool-binary-random; do
        "$ZUPT_MT_REAL_GREP" -Fx "$event" "$directory/events" >/dev/null || valid=0
    done
    if [[ $mode != binary-random-exit ]]; then
        "$ZUPT_MT_REAL_GREP" -Fx tool-binary-zero "$directory/events" >/dev/null || valid=0
    elif "$ZUPT_MT_REAL_GREP" -Fx tool-binary-zero "$directory/events" >/dev/null; then valid=0
    elif [[ $? != 1 ]]; then valid=0
    fi
    if "$ZUPT_MT_REAL_GREP" -F SETUP-FAILURE: "$directory/events" >/dev/null; then valid=0
    elif [[ $? != 1 ]]; then valid=0
    fi
    if [[ $expected == 0 ]]; then
        "$ZUPT_MT_REAL_GREP" -Fx '  MT RESULTS: 14 passed, 0 failed (14 tests)' "$directory/log" >/dev/null || valid=0
        for command in compress extract test; do
            "$ZUPT_MT_REAL_GREP" -Fx "cli-$command" "$directory/events" >/dev/null || valid=0
        done
        [[ ! -f $directory/binary-sizes ]] || IFS= read -r sizes <"$directory/binary-sizes"
        [[ $sizes == '512000 204800' ]] || valid=0
    else
        "$ZUPT_MT_REAL_GREP" -Fx "tool-binary-fault-$mode" "$directory/events" >/dev/null || valid=0
        "$ZUPT_MT_REAL_GREP" -Fx 'Cannot prepare threaded-test binary fixtures' "$directory/log" >/dev/null || valid=0
        if [[ $mode == *-exit ]]; then
            "$ZUPT_MT_REAL_GREP" -F 'producer failure after complete output' "$directory/log" >/dev/null || valid=0
        else
            "$ZUPT_MT_REAL_GREP" -Fx tool-binary-validator "$directory/events" >/dev/null || valid=0
            if [[ $mode != binary-validator-error ]]; then
                "$ZUPT_MT_REAL_GREP" -F 'invalid binary fixture length' "$directory/log" >/dev/null || valid=0
            fi
        fi
        if "$ZUPT_MT_REAL_GREP" -E '^cli-(compress|extract|test)$' "$directory/events" >/dev/null; then scan=0
        else scan=$?
        fi
        [[ $scan == 1 ]] || valid=0
        if "$ZUPT_MT_REAL_GREP" -aE '── T1:|MT RESULTS:' "$directory/log" >/dev/null; then scan=0
        else scan=$?
        fi
        [[ $scan == 1 ]] || valid=0
    fi
    if [[ $valid == 1 ]]; then
        printf 'PASS: threaded binary fixture %s\n' "$mode"
        if [[ $expected == 0 ]]; then printf 'BINARY_FIXTURE_SIZES=%s\n' "$sizes"
        else printf 'BINARY_FIXTURE_STATE %s status=%s cleaned=1 before-codec=1\n' "$mode" "$status"
        fi
    else
        printf 'FAIL: threaded binary fixture %s: expected %s, got %s\n' "$mode" "$expected" "$status" >&2
        cat -- "$directory/log" "$directory/events"
        failures=$((failures + 1))
    fi
}

run_binary_fixture binary-clean 0
for producer in random zero; do
    for fault in exit empty short long; do run_binary_fixture "binary-$producer-$fault" 1; done
done
run_binary_fixture binary-validator-error 1

run_timing() {
    local mode=$1 expected=$2 directory status valid=1 observed= calls= scan phase state result count= summary
    directory=$work/fixture-$mode
    mkdir -p -- "$directory/tmp with spaces"
    unset ZUPT_MT_LIFECYCLE
    export ZUPT_MT_FIXTURE=$mode ZUPT_MT_FAULT=clean
    export ZUPT_MT_EVENT_LOG=$directory/events ZUPT_MT_RECORD=$directory/workspace
    : >"$ZUPT_MT_EVENT_LOG"
    if TMPDIR="$directory/tmp with spaces" PATH=$work/tools:$PATH ZUPT_MT_TOOL_CHILD=1 \
        sh "$root/tests/test_threaded.sh" "$work/cli" >"$directory/log" 2>&1; then status=0
    else status=$?
    fi
    checks=$((checks + 1))
    [[ $status == "$expected" ]] || valid=0
    [[ ! -f $directory/workspace ]] || IFS= read -r observed <"$directory/workspace"
    [[ $observed == "$directory/tmp with spaces"/zupt_mt_* && ! -e $observed && ! -L $observed ]] || valid=0
    if "$ZUPT_MT_REAL_GREP" -F SETUP-FAILURE: "$directory/events" >/dev/null; then valid=0
    elif [[ $? != 1 ]]; then valid=0
    fi
    if calls=$("$ZUPT_MT_REAL_GREP" -aE '^timing-call-' "$directory/events"); then
        [[ $calls == $'timing-call-1 threads=1\ntiming-call-4 threads=4' ]] || valid=0
    else valid=0
    fi
    for phase in 1 4; do
        state=nonempty; result=0
        case $mode in
            "timing-$phase-before") state=missing; result=37 ;;
            "timing-$phase-after") result=37 ;;
            "timing-$phase-missing") state=missing ;;
            "timing-$phase-empty") state=empty ;;
            "timing-$phase-directory") state=directory ;;
        esac
        "$ZUPT_MT_REAL_GREP" -Fx "timing-result-$phase status=$result state=$state" "$directory/events" >/dev/null || valid=0
    done
    summary='  MT RESULTS: 14 passed, 0 failed (14 tests)'
    if [[ $expected == 1 ]]; then
        summary='  MT RESULTS: 13 passed, 1 failed (14 tests)'
        "$ZUPT_MT_REAL_GREP" -Fx "timing-fault-$mode" "$directory/events" >/dev/null || valid=0
        "$ZUPT_MT_REAL_GREP" -Fx "timing stdout $mode" "$directory/log" >/dev/null || valid=0
        "$ZUPT_MT_REAL_GREP" -Fx "timing stderr $mode" "$directory/log" >/dev/null || valid=0
        if count=$("$ZUPT_MT_REAL_GREP" -ac '^  FAIL:' "$directory/log"); then
            [[ $count == 1 ]] || valid=0
        else valid=0
        fi
        "$ZUPT_MT_REAL_GREP" -Fx '  FAIL: Throughput comparison requires successful compression and nonempty regular archives' "$directory/log" >/dev/null || valid=0
        if "$ZUPT_MT_REAL_GREP" -aE '^  N=1:|^  Speedup:|^  OK:   Throughput comparison' "$directory/log" >/dev/null; then scan=0
        else scan=$?
        fi
        [[ $scan == 1 ]] || valid=0
    else
        "$ZUPT_MT_REAL_GREP" -F '  OK:   Throughput comparison (' "$directory/log" >/dev/null || valid=0
    fi
    "$ZUPT_MT_REAL_GREP" -Fx "$summary" "$directory/log" >/dev/null || valid=0
    if [[ $valid == 1 ]]; then
        printf 'PASS: threaded timing %s\n' "$mode"
        printf 'TIMING_STATE %s status=%s cleaned=1 calls=1,4\n' "$mode" "$status"
    else
        printf 'FAIL: threaded timing %s: expected %s, got %s\n' "$mode" "$expected" "$status" >&2
        cat -- "$directory/log" "$directory/events"
        failures=$((failures + 1))
    fi
}

run_timing timing-clean 0
for phase in 1 4; do
    for fault in before after missing empty directory; do run_timing "timing-$phase-$fault" 1; done
done
run_many() {
    local mode=$1 expected=$2 directory status valid=1 observed= calls= scan count= files=1000
    local compress_status=0 extract_status=0 summary='  MT RESULTS: 14 passed, 0 failed (14 tests)'
    directory=$work/fixture-$mode
    mkdir -p -- "$directory/tmp with spaces"
    unset ZUPT_MT_LIFECYCLE
    export ZUPT_MT_FIXTURE=$mode ZUPT_MT_FAULT=clean
    export ZUPT_MT_EVENT_LOG=$directory/events ZUPT_MT_RECORD=$directory/workspace
    : >"$ZUPT_MT_EVENT_LOG"
    if TMPDIR="$directory/tmp with spaces" PATH=$work/tools:$PATH ZUPT_MT_TOOL_CHILD=1 \
        sh "$root/tests/test_threaded.sh" "$work/cli" >"$directory/log" 2>&1; then status=0
    else status=$?
    fi
    checks=$((checks + 1))
    [[ $status == "$expected" ]] || valid=0
    [[ ! -f $directory/workspace ]] || IFS= read -r observed <"$directory/workspace"
    [[ $observed == "$directory/tmp with spaces"/zupt_mt_* && ! -e $observed && ! -L $observed ]] || valid=0
    if "$ZUPT_MT_REAL_GREP" -F SETUP-FAILURE: "$directory/events" >/dev/null; then valid=0
    elif [[ $? != 1 ]]; then valid=0
    fi
    if calls=$("$ZUPT_MT_REAL_GREP" -aE '^many-call-' "$directory/events"); then
        [[ $calls == $'many-call-compress threads=8\nmany-call-extract' ]] || valid=0
    else valid=0
    fi
    case $mode in
        many-compress-after) compress_status=37 ;;
        many-extract-after) extract_status=37 ;;
        many-missing) files=999 ;;
        many-extra) files=1001 ;;
    esac
    "$ZUPT_MT_REAL_GREP" -Fx "many-compress-result status=$compress_status state=nonempty" "$directory/events" >/dev/null || valid=0
    "$ZUPT_MT_REAL_GREP" -Fx "many-extract-result files=$files source-preserved=1" "$directory/events" >/dev/null || valid=0
    "$ZUPT_MT_REAL_GREP" -Fx "many-extract-status=$extract_status" "$directory/events" >/dev/null || valid=0
    if [[ $expected == 1 ]]; then
        summary='  MT RESULTS: 13 passed, 1 failed (14 tests)'
        "$ZUPT_MT_REAL_GREP" -Fx "many-fault-$mode" "$directory/events" >/dev/null || valid=0
        "$ZUPT_MT_REAL_GREP" -Fx "many stdout $mode" "$directory/log" >/dev/null || valid=0
        "$ZUPT_MT_REAL_GREP" -Fx "many stderr $mode" "$directory/log" >/dev/null || valid=0
        if count=$("$ZUPT_MT_REAL_GREP" -ac '^  FAIL:' "$directory/log"); then
            [[ $count == 1 ]] || valid=0
        else valid=0
        fi
        "$ZUPT_MT_REAL_GREP" -F '  FAIL: 1000 small files N=8' "$directory/log" >/dev/null || valid=0
        if "$ZUPT_MT_REAL_GREP" -F '  OK:   1000 small files N=8' "$directory/log" >/dev/null; then scan=0
        else scan=$?
        fi
        [[ $scan == 1 ]] || valid=0
    else
        "$ZUPT_MT_REAL_GREP" -F '  OK:   1000 small files N=8' "$directory/log" >/dev/null || valid=0
    fi
    "$ZUPT_MT_REAL_GREP" -Fx "$summary" "$directory/log" >/dev/null || valid=0
    if [[ $valid == 1 ]]; then
        printf 'PASS: threaded many-file %s\n' "$mode"
        printf 'MANY_STATE %s status=%s files=%s source-preserved=1 cleaned=1\n' "$mode" "$status" "$files"
    else
        printf 'FAIL: threaded many-file %s: expected %s, got %s\n' "$mode" "$expected" "$status" >&2
        cat -- "$directory/log" "$directory/events"
        failures=$((failures + 1))
    fi
}

run_many many-clean 0
for fault in compress-after extract-after corrupt rename relocate missing extra; do run_many "many-$fault" 1; done
if [[ $checks != 79 ]]; then
    printf 'FAIL: expected 79 threaded controls, observed %s\n' "$checks" >&2
    failures=$((failures + 1))
fi
if ((failures)); then
    printf 'FAIL: threaded harness: %s/%s checks failed\n' "$failures" "$checks" >&2
    exit 1
fi
printf 'PASS: threaded harness: %s checks (synthetic CLI only)\n' "$checks"
