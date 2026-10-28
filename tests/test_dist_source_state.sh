#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

set -Eeuo pipefail

if [[ ${ZUPT_DIST_TOOL_CHILD:-0} == 1 ]]; then
    tool=${0##*/}
    case $tool in
        git)
            real_tool=$ZUPT_DIST_REAL_GIT
            if [[ ${1:-} != archive ]]; then exec "$real_tool" "$@"; fi
            ;;
        gzip) real_tool=$ZUPT_DIST_REAL_GZIP ;;
        *) printf 'FIXTURE SETUP FAILURE: unknown tool\n' >&2; exit 125 ;;
    esac
    if [[ $ZUPT_DIST_FAULT_TOOL != "$tool" ]]; then
        exec "$real_tool" "$@"
    fi
    printf 'DIST-PRODUCER-FAULT: %s %s\n' "$tool" "$ZUPT_DIST_FAULT_MODE" >&2
    case $ZUPT_DIST_FAULT_MODE in
        plausible)
            if ! "$real_tool" "$@"; then
                printf 'FIXTURE SETUP FAILURE: real producer failed\n' >&2
                exit 125
            fi
            ;;
        empty) ;;
        *) printf 'FIXTURE SETUP FAILURE: unknown mode\n' >&2; exit 125 ;;
    esac
    exit 73
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/zupt-dist-state.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT HUP INT TERM
repo=$scratch/source
mkdir -p "$repo/include" "$repo/sdk"
cp -- "$root/Makefile" "$repo/Makefile"
cp -- "$root/include/zupt.h" "$repo/include/zupt.h"
cp -- "$root/sdk/Makefile.sdk" "$repo/sdk/Makefile.sdk"
printf '1788134400\n' >"$repo/.source-date-epoch"
printf '*.o\n' >"$repo/.gitignore"
printf 'committed source\n' >"$repo/source.c"
export ZUPT_DIST_AUDIT_MARKER=$scratch/audit-ran
# shellcheck disable=SC2016 # The generated fixture reads the marker at runtime.
printf '#!/usr/bin/env bash\n: > "$ZUPT_DIST_AUDIT_MARKER"\n' >"$repo/source-audit.sh"
git -C "$repo" init -q
git -C "$repo" add -- .
git -C "$repo" -c user.name='ZUPT distribution test' \
    -c user.email='distribution-test@invalid.example' -c commit.gpgsign=false \
    commit -qm 'Create source fixture'

archive=$scratch/source.tar.gz
log=$scratch/dist.log
passed=0

run_dist() {
    make -C "$repo" --no-print-directory SOURCE_AUDIT=source-audit.sh \
        DIST_TARBALL="$archive" dist >"$log" 2>&1
}

expect_pass() {
    if ! run_dist; then
        cat "$log" >&2
        printf 'FAIL: %s\n' "$1" >&2
        exit 1
    fi
    test -s "$archive"
    passed=$((passed + 1))
    printf 'PASS: %s\n' "$1"
}

expect_dirty_rejection() {
    # Leave an existing output in place to check that rejection does not
    # replace it with an archive of an older commit.
    cp -- "$archive" "$scratch/previous.tar.gz"
    if run_dist; then
        printf 'FAIL: dist accepted %s\n' "$1" >&2
        exit 1
    fi
    if ! grep -Fq 'dist requires a clean committed source tree' "$log"; then
        cat "$log" >&2
        printf 'FAIL: missing source-state diagnostic for %s\n' "$1" >&2
        exit 1
    fi
    cmp -- "$archive" "$scratch/previous.tar.gz"
    passed=$((passed + 1))
    printf 'PASS: dist rejects %s without replacing the archive\n' "$1"
}

expect_pass 'clean committed source is archived'
cp -- "$repo/source.c" "$scratch/original.c"
printf 'changed source\n' >"$repo/source.c"
expect_dirty_rejection 'unstaged source changes'
git -C "$repo" add -- source.c
expect_dirty_rejection 'staged source changes'
cp -- "$scratch/original.c" "$repo/source.c"
expect_dirty_rejection 'staged source differing from the restored worktree'
git -C "$repo" add -- source.c

rm -- "$repo/source.c"
expect_dirty_rejection 'a deleted tracked source'
cp -- "$scratch/original.c" "$repo/source.c"
printf 'new regression\n' >"$repo/new-test.c"
expect_dirty_rejection 'an untracked source or test'
rm -- "$repo/new-test.c"
# Command substitution strips trailing newlines. A filename consisting of
# one newline must still be reported as untracked by the source-state gate.
printf 'new source\n' >"$repo/"$'\n'
expect_dirty_rejection 'a newline-only untracked filename'
rm -- "$repo/"$'\n'

printf 'ignored build output\n' >"$repo/generated.o"
expect_pass 'ignored build outputs do not change the committed archive'
cmp -- "$archive" "$scratch/previous.tar.gz"

# Forward successful producer output unchanged; only their exit statuses are
# injected. This is a source-state fixture, not a native package or scanner test.
export ZUPT_DIST_REAL_GIT ZUPT_DIST_REAL_GZIP
ZUPT_DIST_REAL_GIT=$(command -v git)
ZUPT_DIST_REAL_GZIP=$(command -v gzip)
shims=$scratch/bin
mkdir -- "$shims"
for tool in git gzip; do
    cp -- "${BASH_SOURCE[0]}" "$shims/$tool"
    chmod 700 "$shims/$tool"
done
PATH="$shims:$PATH" ZUPT_DIST_TOOL_CHILD=1 ZUPT_DIST_FAULT_TOOL=none \
    expect_pass 'successful producer shims preserve the committed export'
cmp -- "$archive" "$scratch/previous.tar.gz"

failures=0
expect_producer_rejection() {
    local tool=$1 mode=$2 output=$3 status
    log=$scratch/$tool-$mode-$output.log
    rm -f -- "$ZUPT_DIST_AUDIT_MARKER"
    if [[ $output == existing ]]; then
        cp -- "$scratch/previous.tar.gz" "$archive"
        ln -- "$archive" "$scratch/held-output"
    else
        rm -f -- "$archive"
    fi
    if PATH="$shims:$PATH" ZUPT_DIST_TOOL_CHILD=1 ZUPT_DIST_FAULT_TOOL="$tool" \
        ZUPT_DIST_FAULT_MODE="$mode" run_dist; then
        status=0
    else
        status=$?
    fi
    printf 'CASE: %s/%s/%s: make status %s\n' "$tool" "$mode" "$output" "$status"
    cat -- "$log"
    if [[ $status != 2 || -e $ZUPT_DIST_AUDIT_MARKER ]] || \
       ! grep -Fq "DIST-PRODUCER-FAULT: $tool $mode" "$log" || \
       grep -Fq 'FIXTURE SETUP FAILURE:' "$log" || \
       grep -Fq 'Reproducible source tarball:' "$log" || \
       { [[ $output == absent ]] && [[ -e $archive || -L $archive ]]; } || \
       { [[ $output == existing ]] && {
           [[ ! $archive -ef $scratch/held-output ]] || \
           ! cmp -s -- "$archive" "$scratch/previous.tar.gz"; }; }; then
        printf 'FAIL: producer rejection %s/%s/%s\n' "$tool" "$mode" "$output" >&2
        failures=$((failures + 1))
    else
        passed=$((passed + 1))
        printf 'PASS: failed %s/%s leaves %s output unchanged and skips scanner\n' "$tool" "$mode" "$output"
    fi
    if [[ $output == existing ]]; then rm -- "$scratch/held-output"; fi
}
for tool in git gzip; do
    for mode in empty plausible; do
        for output in absent existing; do
            expect_producer_rejection "$tool" "$mode" "$output"
        done
    done
done
printf 'Distribution source-state controls: %s passed\n' "$passed"
if (( failures != 0 )); then
    printf 'FAIL: distribution producer controls: %s failed\n' "$failures" >&2
    exit 1
fi
