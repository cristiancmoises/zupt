#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Supervisor controls only; real codec and sanitizer tests run separately.
set -eu
self=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")

# Narrow self-copies model usable output followed by a producer failure.
bcj_fixture_error() {
    printf 'BCJ-FIXTURE-ERROR: %s\n' "$*" >&2
    exit 125
}

bcj_injected_failure() {
    local stage=$1 level=$2 line
    for ((line=1; line<=20; line++)); do
        printf 'BCJ diagnostic %s L%s %02d\n' "$stage" "$level" "$line" >&2
    done
    printf 'BCJ-INJECTED-%s-L%s\n' "$stage" "$level" >&2
    exit 73
}

if [[ ${0##*/} == zupt || ${0##*/} == find ]]; then
    mode=${EXACT_SIZE_BCJ_MODE:?}
    level=${EXACT_SIZE_BCJ_LEVEL:?}
    case $mode in clean|compression|extraction|enumeration|extra|missing|corrupt) ;;
        *) bcj_fixture_error 'unknown mode' ;; esac
    [[ $level == 5 || $level == 9 ]] || bcj_fixture_error 'unknown level'
    if [[ ${0##*/} == zupt ]]; then
        case ${1:-} in
            c)
                [[ $# == 5 && $2 == -l && ( $3 == 5 || $3 == 9 ) && $5 == "$ZUPT_BIN" ]] ||
                    bcj_fixture_error 'unexpected compression arguments'
                current=$3; archive=$4; directory=${archive%/*}
                [[ $archive == "$directory/a$current.zupt" ]] || bcj_fixture_error 'archive name'
                operation=c
                ;;
            x)
                [[ $# == 4 && $2 == -o ]] || bcj_fixture_error 'unexpected extraction arguments'
                output=$3; archive=$4; directory=${archive%/*}
                case $archive in "$directory/a5.zupt") current=5 ;; "$directory/a9.zupt") current=9 ;;
                    *) bcj_fixture_error 'archive name' ;; esac
                [[ $output == "$directory/o$current" && -d $output ]] || bcj_fixture_error 'output directory'
                operation=x
                ;;
            *) bcj_fixture_error 'unexpected CLI operation' ;;
        esac
    else
        [[ ( $# == 3 || $# == 4 ) && $2 == -type && $3 == f ]] ||
            bcj_fixture_error 'unexpected enumeration arguments'
        [[ $# == 3 || $4 == -print0 ]] || bcj_fixture_error 'unexpected enumeration format'
        output=$1; directory=${output%/*}
        case $output in "$directory/o5") current=5 ;; "$directory/o9") current=9 ;;
            *) bcj_fixture_error 'enumeration directory' ;; esac
        operation=f
    fi
    [[ $directory == "$EXACT_SIZE_BCJ_TMP/"* && ${directory#"$EXACT_SIZE_BCJ_TMP/"} != */* ]] ||
        bcj_fixture_error 'operation outside the owned scratch directory'
    printf '%s %s\n' "$operation" "$current" >>"$EXACT_SIZE_BCJ_TRACE"
    case $operation in
        c)
            cp -- "$ZUPT_BIN" "$archive"
            if [[ $mode == compression && $current == "$level" ]]; then
                bcj_injected_failure compression "$current"
            fi
            ;;
        x)
            cmp -- "$archive" "$ZUPT_BIN" || bcj_fixture_error 'unusable synthetic archive'
            if [[ $mode != missing || $current != "$level" ]]; then
                cp -- "$archive" "$output/fixture.bin"
            fi
            if [[ $current == "$level" ]]; then
                case $mode in
                    extraction) bcj_injected_failure extraction "$current" ;;
                    extra) printf 'extra member\n' >"$output/extra.bin" ;;
                    corrupt) printf 'corrupt bytes\n' >"$output/fixture.bin" ;;
                esac
            fi
            ;;
        f)
            "$EXACT_SIZE_REAL_FIND" "$@"
            if [[ $mode == enumeration && $current == "$level" ]]; then
                bcj_injected_failure enumeration "$current"
            fi
            ;;
    esac
    exit 0
fi

if [[ ${0##*/} == t ]]; then
    printf 'RUN\n' >>"$EXACT_SIZE_RUN_LOG"
    if [[ ${EXACT_SIZE_RUN_SIGNAL:-0} == 1 ]]; then
        kill -TERM "$$"
    fi
    exit "${EXACT_SIZE_RUN_STATUS:-0}"
fi

if [[ ${1:-} == --fake-cc ]]; then
    flavor=$2
    shift 2
    case ${1:-} in
        --version) printf '%s version synthetic\n' "$flavor"; exit 0 ;;
        -dumpmachine) printf 'x86_64-unknown-linux-gnu\n'; exit 0 ;;
    esac
    printf '%s\t' "$flavor" "$@" >>"$EXACT_SIZE_CC_LOG"
    printf '\n' >>"$EXACT_SIZE_CC_LOG"
    output=
    source=
    compile=0
    previous=
    for argument in "$@"; do
        [[ $previous != -o ]] || output=$argument
        [[ $argument != -c ]] || compile=1
        case $argument in *.c) source=$argument ;; esac
        previous=$argument
    done
    if [[ $compile == 1 && $source == "${EXACT_SIZE_FAIL_SOURCE:-none}" ]]; then
        for ((line=1; line<=20; line++)); do
            printf 'synthetic compiler diagnostic %02d\n' "$line" >&2
        done
        printf 'EXACT-SIZE-INJECTED-COMPILE-FAILURE\n' >&2
        exit 42
    fi
    if [[ $compile == 0 && ${EXACT_SIZE_FAIL_LINK:-0} == 1 ]]; then
        printf 'EXACT-SIZE-INJECTED-LINK-FAILURE\n' >&2
        exit 43
    fi
    test -n "$output"
    cp -- "$self" "$output"
    chmod +x "$output"
    exit 0
fi

test_project=${1:-$(dirname -- "$(dirname -- "$self")")}
test_project=$(CDPATH='' cd -- "$test_project" && pwd -P)
test_tmp=$(mktemp -d)
trap 'rm -rf -- "$test_tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$test_tmp/project/tests" "$test_tmp/project/sdk" "$test_tmp/bin"
cp "$test_project/Makefile" "$test_tmp/project/"
cp "$test_project/sdk/Makefile.sdk" "$test_tmp/project/sdk/"
cp "$test_project/tests/test_codec_exact_size.sh" "$test_tmp/project/tests/"
# A literal GCC call must fail, not accidentally invoke the host compiler.
false_program=$(type -P false)
test -x "$false_program"
ln -s "$false_program" "$test_tmp/bin/gcc"
export EXACT_SIZE_REAL_FIND="$(type -P find)"
test -x "$EXACT_SIZE_REAL_FIND"
export PATH="$test_tmp/bin:$PATH"
unset BASH_ENV ENV
export ZUPT_BIN="$test_tmp/no-real-cli"
export CPPFLAGS='-DEXACT_SIZE_CPP_MARKER=1'
export CFLAGS='-O2 -g -Wcast-align -Werror -fno-omit-frame-pointer'
export LDFLAGS='-Wl,--exact-size-link-marker'
export LDLIBS='-lexact_size_marker'
unset VV_CAST_ALIGN_FLAGS EXACT_SIZE_FAIL_SOURCE EXACT_SIZE_FAIL_LINK
unset EXACT_SIZE_RUN_STATUS EXACT_SIZE_RUN_SIGNAL

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

has_argument() {
    local expected=$1 argument
    shift
    for argument in "$@"; do
        [[ $argument != "$expected" ]] || return 0
    done
    return 1
}

check_calls() {
    local flavor=$1 record argument source compile_count=0 link_count=0
    local -a arguments
    local seen_sources=''
    test -s "$EXACT_SIZE_CC_LOG" || fail 'chosen CC was not invoked'
    while IFS= read -r record; do
        IFS=$'\t' read -r -a arguments <<<"$record"
        [[ ${arguments[0]} == "$flavor" ]] || fail 'wrong compiler driver'
        has_argument -fsanitize=address "${arguments[@]}" || fail 'missing ASan instrumentation'
        has_argument -O2 "${arguments[@]}" || fail 'caller CFLAGS were dropped'
        has_argument -Wcast-align "${arguments[@]}" || fail 'strict alignment policy was dropped'
        if has_argument -c "${arguments[@]}"; then
            compile_count=$((compile_count+1))
            has_argument -DEXACT_SIZE_CPP_MARKER=1 "${arguments[@]}" || fail 'caller CPPFLAGS were dropped'
            has_argument -Wl,--exact-size-link-marker "${arguments[@]}" && fail 'linker flags entered compilation'
            source=
            for argument in "${arguments[@]}"; do
                case $argument in *.c) source=$argument ;; esac
            done
            case $source in
                tests/test_codec_exact_size.c|src/vaptvupt_api.c|src/vv_ans.c|src/vv_bcj.c|src/vv_decoder.c|src/vv_encoder.c|src/vv_huffman.c|src/vv_simd.c|src/vv_xxh64.c) ;;
                *) fail "unexpected source: $source" ;;
            esac
            case " $seen_sources " in
                *" $source "*) fail "duplicate source: $source" ;;
            esac
            seen_sources="$seen_sources $source"
            case "$flavor:$source" in
                clang:src/vv_ans.c|clang:src/vv_simd.c)
                    has_argument -Wno-cast-align "${arguments[@]}" || fail "missing local exception for $source"
                    ;;
                *)
                    if has_argument -Wno-cast-align "${arguments[@]}"; then
                        fail "alignment exception leaked to $flavor:$source"
                    fi
                    ;;
            esac
        else
            link_count=$((link_count+1))
            has_argument -Wl,--exact-size-link-marker "${arguments[@]}" || fail 'caller LDFLAGS were dropped'
            has_argument -lexact_size_marker "${arguments[@]}" || fail 'caller LDLIBS were dropped'
            for argument in "${arguments[@]}"; do
                case $argument in *.c) fail 'source was compiled at link time' ;; esac
            done
        fi
    done <"$EXACT_SIZE_CC_LOG"
    [[ $compile_count == 9 && $link_count == 1 ]] || fail "expected nine sanitized sources and one link, got $compile_count/$link_count"
    [[ $(wc -l <"$EXACT_SIZE_RUN_LOG") == 1 ]] || fail 'synthetic output did not execute exactly once'
}

for flavor in gcc clang; do
    export CC="bash $self --fake-cc $flavor"
    for invocation in direct make make-overrides; do
        export EXACT_SIZE_CC_LOG="$test_tmp/$flavor-$invocation.calls"
        export EXACT_SIZE_RUN_LOG="$test_tmp/$flavor-$invocation.runs"
        if [[ $invocation == direct ]]; then
            if ! (cd "$test_tmp/project" && bash tests/test_codec_exact_size.sh) >"$test_tmp/$flavor-$invocation.log" 2>&1; then
                sed 's/^/    /' "$test_tmp/$flavor-$invocation.log" >&2
                fail "$flavor direct invocation failed"
            fi
        else
            if [[ $invocation == make-overrides ]]; then
                export MAKEFLAGS='-- CC=false CPPFLAGS=-DOUTER_FLAGS CFLAGS=-DOUTER_FLAGS'
                export MAKEOVERRIDES='CC=false CPPFLAGS=-DOUTER_FLAGS CFLAGS=-DOUTER_FLAGS'
                export MFLAGS='-s'
            fi
            # Parent command-line overrides must not replace the fixture CC.
            if ! (cd "$test_tmp/project" && env -u MAKEFLAGS -u MAKEOVERRIDES -u MFLAGS \
                "${MAKE:-make}" V=1 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 AFL_CC=false test-codec-exact-size) >"$test_tmp/$flavor-$invocation.log" 2>&1; then
                sed 's/^/    /' "$test_tmp/$flavor-$invocation.log" >&2
                fail "$flavor Makefile invocation failed"
            fi
        fi
        check_calls "$flavor"
        printf 'PASS: synthetic %s %s compiler/flags/local-exception/ASan contract\n' "$flavor" "$invocation"
    done
done

export CC="bash $self --fake-cc clang"
for failure in compile link status signal; do
    export EXACT_SIZE_CC_LOG="$test_tmp/failure-$failure.calls"
    export EXACT_SIZE_RUN_LOG="$test_tmp/failure-$failure.runs"
    export EXACT_SIZE_FAIL_SOURCE=none EXACT_SIZE_FAIL_LINK=0
    export EXACT_SIZE_RUN_STATUS=0 EXACT_SIZE_RUN_SIGNAL=0
    case $failure in
        compile)
            export EXACT_SIZE_FAIL_SOURCE=src/vv_decoder.c
            failure_marker=EXACT-SIZE-INJECTED-COMPILE-FAILURE ;;
        link)
            export EXACT_SIZE_FAIL_LINK=1
            failure_marker=EXACT-SIZE-INJECTED-LINK-FAILURE ;;
        status) export EXACT_SIZE_RUN_STATUS=99 ;;
        signal) export EXACT_SIZE_RUN_SIGNAL=1 ;;
    esac
    if (cd "$test_tmp/project" && bash tests/test_codec_exact_size.sh) >"$test_tmp/failure-$failure.log" 2>&1; then
        fail "$failure failure was accepted"
    fi
    case $failure in
        compile|link)
            grep -F "$failure_marker" "$test_tmp/failure-$failure.log" >/dev/null || fail "$failure diagnostic was hidden"
            if [[ $failure == compile ]]; then
                [[ $(grep -c 'synthetic compiler diagnostic' "$test_tmp/failure-$failure.log") == 20 ]] || fail 'compiler diagnostics were truncated'
            fi
            test ! -e "$EXACT_SIZE_RUN_LOG" || fail 'output ran after compiler failure'
            ;;
        status|signal)
            [[ $(wc -l <"$EXACT_SIZE_RUN_LOG") == 1 ]] || fail 'failing synthetic output did not execute'
            ;;
    esac
    printf 'PASS: synthetic %s failure returns nonzero and preserves failure handling\n' "$failure"
done
printf 'PASS: ten orchestration cases; real exact-size/BCJ and ASan validation remain separate\n'

# Exercise the actual supervisor, not a second implementation of its verdict.
unset EXACT_SIZE_FAIL_SOURCE EXACT_SIZE_FAIL_LINK EXACT_SIZE_RUN_STATUS EXACT_SIZE_RUN_SIGNAL
unset MAKEFLAGS MAKEOVERRIDES MFLAGS
cp -- "$self" "$test_tmp/project/zupt"
cp -- "$self" "$test_tmp/bin/find"
chmod +x "$test_tmp/project/zupt" "$test_tmp/bin/find"
export ZUPT_BIN="$test_tmp/fixture.bin"
printf 'literal BCJ fixture\000\001\377\n' >"$ZUPT_BIN"
bcj_failures=0

bcj_problem() {
    printf 'FAIL: BCJ supervisor %s L%s: %s\n' "$mode" "$level" "$*" >&2
    case_failed=1
}

bcj_case() {
    local mode=$1 level=$2 expected=$3 status log trace current count
    local case_failed=0
    log=$test_tmp/bcj-$mode-$level.log
    trace=$test_tmp/bcj-$mode-$level.expected
    export EXACT_SIZE_BCJ_MODE=$mode EXACT_SIZE_BCJ_LEVEL=$level
    export EXACT_SIZE_BCJ_TMP=$test_tmp/bcj-$mode-$level
    export EXACT_SIZE_BCJ_TRACE=$test_tmp/bcj-$mode-$level.trace
    export EXACT_SIZE_CC_LOG=$test_tmp/bcj-$mode-$level.calls
    export EXACT_SIZE_RUN_LOG=$test_tmp/bcj-$mode-$level.runs
    mkdir -- "$EXACT_SIZE_BCJ_TMP"
    if (cd "$test_tmp/project" && TMPDIR="$EXACT_SIZE_BCJ_TMP" bash tests/test_codec_exact_size.sh) >"$log" 2>&1; then
        status=0
    else
        status=$?
    fi
    printf 'BCJ supervisor case %s L%s: actual status %s, expected %s\n' "$mode" "$level" "$status" "$expected"
    cat -- "$log"
    [[ $status == "$expected" ]] || bcj_problem "unexpected supervisor status $status"
    check_calls clang

    # Failed stages must not feed dependent stages; the other level still runs.
    {
        for current in 5 9; do
            printf 'c %s\n' "$current"
            if [[ $current == "$level" && $mode == compression ]]; then continue; fi
            printf 'x %s\n' "$current"
            if [[ $current == "$level" && $mode == extraction ]]; then continue; fi
            printf 'f %s\n' "$current"
        done
    } >"$trace"
    cmp -- "$trace" "$EXACT_SIZE_BCJ_TRACE" || bcj_problem 'wrong stage/level trace'
    for current in 5 9; do
        if count=$(grep -Fc "✓ BCJ roundtrip L$current (binary fixture) byte-exact" "$log"); then
            :
        else
            [[ $? == 1 ]] || fail 'cannot read BCJ verdicts'
        fi
        if [[ $expected == 0 || $current != "$level" ]]; then
            [[ $count == 1 ]] || bcj_problem "unaffected L$current did not pass exactly once"
        else
            [[ $count == 0 ]] || bcj_problem "affected L$current was falsely approved"
        fi
    done
    case $mode in
        compression|extraction|enumeration)
            grep -F "BCJ L$level $mode failed (status 73)" "$log" >/dev/null || bcj_problem 'stage/level/status diagnostic missing'
            grep -F "BCJ-INJECTED-$mode-L$level" "$log" >/dev/null || bcj_problem 'injected marker missing'
            if count=$(grep -cF "BCJ diagnostic $mode L$level " "$log"); then :
            else [[ $? == 1 ]] || fail 'cannot read BCJ diagnostics'; fi
            [[ $count == 20 ]] || bcj_problem 'producer diagnostics missing or truncated'
            ;;
    esac
    if [[ $case_failed == 0 ]]; then
        printf 'PASS: BCJ supervisor %s L%s\n' "$mode" "$level"
    else
        bcj_failures=$((bcj_failures+1))
    fi
}

bcj_case clean 5 0
for level in 5 9; do
    bcj_case compression "$level" 1
    bcj_case extraction "$level" 1
done
for mode in enumeration extra missing corrupt; do bcj_case "$mode" 5 1; done
[[ $bcj_failures == 0 ]] || fail "$bcj_failures of nine BCJ supervisor cases failed"
printf 'PASS: nine BCJ supervisor cases; synthetic CLI/compiler controls, not codec or sanitizer execution\n'
