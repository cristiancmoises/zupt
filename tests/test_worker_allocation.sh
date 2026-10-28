#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Exercise worker allocation failure and atomic output through the real CLI.
set -Eeuo pipefail
export LC_ALL=C
umask 077

case $(uname -s) in
    Linux) ;;
    *) echo 'SKIP: worker allocation injection requires native Linux'; exit 0 ;;
esac
target=$("${CC:-cc}" -dumpmachine)
case $target in
    *android*) echo 'SKIP: worker allocation injection requires native Linux'; exit 0 ;;
    *-linux-*) ;;
    *) echo 'SKIP: worker allocation injection requires a Linux compiler target'; exit 0 ;;
esac
if [[ ${target%%-*} != "$(uname -m)" ]]; then
    echo 'SKIP: worker allocation injection does not run cross-compiled executables'
    exit 0
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/zupt-worker-allocation.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    printf 'FAIL: worker allocation: %s\n' "$*" >&2
    exit 1
}

run_logged() {
    local log=$1 status
    shift
    if "$@" >"$log" 2>&1; then status=0; else status=$?; fi
    printf 'WORKER-ALLOC COMMAND %s status=%s\n' "${log##*/}" "$status" || return 125
    cat -- "$log" || return 125
    return "$status"
}

reject_diagnostics() {
    local log=$1 status
    if grep -aE 'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:|WORKER-ALLOC FIXTURE-ERROR|Thread creation failed' "$log"; then
        fail "unexpected diagnostic in ${log##*/}"
    else
        status=$?
        [[ $status == 1 ]] || fail "cannot inspect ${log##*/}"
    fi
}

command -v timeout >/dev/null
mkdir -p "$work/project/src" "$work/project/include" "$work/project/sdk"
cp -- "$root/Makefile" "$work/project/"
cp -- "$root/sdk/Makefile.sdk" "$work/project/sdk/"
cp -- "$root"/src/*.c "$root"/src/*.h "$work/project/src/"
cp -- "$root"/include/*.h "$work/project/include/"

# Linker wrapping must remain visible across separately compiled objects.
# Flag lists intentionally use the same whitespace splitting as Make recipes.
# shellcheck disable=SC2086
run_logged "$work/injector-build.log" "${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS--O2 -g} \
    -std=c11 -Wall -Wextra -Werror -Wmissing-prototypes -Wstrict-prototypes \
    -pthread -fno-lto -c "$root/tests/test_worker_allocation.c" -o "$work/injector.o"
run_logged "$work/cli-build.log" "${MAKE:-make}" -C "$work/project" -j1 V=1 \
    CC="${CC:-cc}" CPPFLAGS="${CPPFLAGS-}" CFLAGS="${CFLAGS--O2 -g} -fno-lto" \
    LDFLAGS="${LDFLAGS-} -fno-lto" \
    LDLIBS="${LDLIBS-} \"$work/injector.o\" -Wl,--wrap=malloc,--wrap=pthread_create" \
    WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 all
cli=$work/project/zupt
[[ -x $cli ]] || fail 'private CLI was not built'
cd -- "$work"
python3 - <<'PY'
with open('input.dat', 'wb') as output:
    output.write(bytes(range(256)) * 256)
PY
cp -- input.dat input.expected
printf 'previous destination must survive\n' >destination.expected

run_case() {
    local mode=$1 destination=$2 expected=$3 case_dir log status count
    case_dir=$work/$mode-$destination
    log=$work/$mode-$destination.log
    mkdir -- "$case_dir"
    if [[ $destination == existing ]]; then
        cp -- destination.expected "$case_dir/archive.zupt"
    fi
    if run_logged "$log" timeout --kill-after=2s 10s \
        env ZUPT_TEST_WORKER_ALLOC="$mode" "$cli" compress -y -s -t 2 -b 65536 \
        "$case_dir/archive.zupt" input.dat; then
        status=0
    else
        status=$?
    fi
    [[ $status == "$expected" ]] || fail "$mode/$destination expected exit $expected, got $status"
    reject_diagnostics "$log"

    # Thread scheduling may reorder independent start/done lines, not the
    # worker-local allocation sequence checked by the C fixture itself.
    {
        printf '%s\n' 'WORKER-ALLOC START 0' 'WORKER-ALLOC START 1' \
            'WORKER-ALLOC MALLOC 0 76288' 'WORKER-ALLOC DONE 0' 'WORKER-ALLOC DONE 1'
        if [[ $mode != cbuf ]]; then printf '%s\n' 'WORKER-ALLOC MALLOC 0 65536'; fi
        if [[ $mode != none ]]; then printf 'WORKER-ALLOC INJECT %s\n' "$mode"; fi
    } >"$work/expected-events"
    sort "$work/expected-events" >"$work/expected-sorted"
    grep -a '^WORKER-ALLOC' "$log" >"$work/actual-events"
    sort "$work/actual-events" >"$work/actual-sorted"
    cmp -- "$work/expected-sorted" "$work/actual-sorted" || fail "$mode/$destination event inventory differs"

    if [[ $mode == none ]]; then
        if grep -aF 'Block error:' "$log"; then
            fail 'clean STORE compression reported a block error'
        else
            status=$?
            [[ $status == 1 ]] || fail 'cannot inspect clean block diagnostics'
        fi
        run_logged "$work/clean-test.log" timeout --kill-after=2s 10s \
            env ZUPT_TEST_WORKER_ALLOC=none "$cli" test "$case_dir/archive.zupt"
        reject_diagnostics "$work/clean-test.log"
        mkdir -- "$case_dir/out"
        run_logged "$work/clean-extract.log" timeout --kill-after=2s 10s \
            env ZUPT_TEST_WORKER_ALLOC=none "$cli" extract -t 1 -o "$case_dir/out" "$case_dir/archive.zupt"
        reject_diagnostics "$work/clean-extract.log"
        cmp -- input.expected "$case_dir/out/input.dat"
        rm -- "$case_dir/out/input.dat"
        rmdir -- "$case_dir/out"
        rm -- "$case_dir/archive.zupt"
    else
        if count=$(grep -aFxc '  Block error: Out of memory' "$log"); then
            [[ $count == 1 ]] || fail "$mode/$destination has ambiguous out-of-memory diagnostics"
        else
            fail "$mode/$destination lacks the exact block out-of-memory diagnostic"
        fi
        if [[ $destination == existing ]]; then
            [[ ! -L $case_dir/archive.zupt ]] || fail 'destination became a symlink'
            cmp -- destination.expected "$case_dir/archive.zupt"
            rm -- "$case_dir/archive.zupt"
        else
            [[ ! -e $case_dir/archive.zupt && ! -L $case_dir/archive.zupt ]] || fail 'failed compression published an archive'
        fi
    fi
    cmp -- input.expected input.dat
    # Remove only expected files above; any hidden private archive is a failure.
    rmdir -- "$case_dir" || fail "$mode/$destination left unexpected output entries"
    printf 'PASS: worker allocation %s/%s; exact process, worker and output checks\n' "$mode" "$destination"
}

run_case none absent 0
for mode in cbuf payload; do
    run_case "$mode" absent 1
    run_case "$mode" existing 1
done
printf 'PASS: worker allocation: five real-CLI cases; no default-thread memory claim\n'
