#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

bin=${1:-./zupt}
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
case $bin in
    /*) ;;
    *) bin="$(pwd -P)/${bin#./}" ;;
esac
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-bench-safety.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# CodeQL #7 reported the old lstat(child) -> recursive pathname operation as
# cpp/toctou-race-condition. Keep the platform-specific cleanup primitives in
# the source gate as well as exercising the runtime symlink boundary below.
cleanup_source=$repo_root/src/zupt_main.c
grep -Fq 'static int zupt_remove_temp_tree_fd(int directory_fd)' \
    "$cleanup_source" || fail 'POSIX descriptor-relative cleanup is missing'
grep -Fq 'unlinkat(parent_fd, entry->d_name, 0)' "$cleanup_source" ||
    fail 'POSIX leaf cleanup is not unlinkat-relative'
grep -Fq 'directory_handle, data.cFileName, 1, 0)' "$cleanup_source" ||
    fail 'Windows recursive cleanup is not handle-relative'
grep -Fq 'FILE_OPEN_REPARSE_POINT' "$cleanup_source" ||
    fail 'Windows cleanup no longer opens reparse points without following'
grep -Fq 'zupt_win_delete_cleanup_entry(' "$cleanup_source" ||
    fail 'Windows cleanup lacks identity-checked handle deletion'
grep -Fq 'current.nFileIndexLow == expected->nFileIndexLow' "$cleanup_source" ||
    fail 'Windows cleanup no longer rejects a close/reopen name exchange'
if grep -Fq 'RemoveDirectoryW(full)' "$cleanup_source"; then
    fail 'Windows root cleanup restored post-handle pathname deletion'
fi
if grep -Fq 'lstat(child' "$cleanup_source" ||
   grep -Fq 'zupt_remove_temp_tree(child' "$cleanup_source"; then
    fail 'temporary cleanup restored a check-then-use pathname traversal'
fi

case $(uname -s 2>/dev/null || printf unknown) in
    MINGW*|MSYS*|CYGWIN*)
        "$bin" bench --compare >/dev/null 2>&1 ||
            fail 'native Windows handle-relative benchmark cleanup failed'
        printf 'SKIP: adversarial POSIX symlink injection is not native on Windows\n'
        printf 'private Windows handle-relative benchmark workspace: PASS\n'
        exit 0
        ;;
esac

printf 'benchmark sentinel must remain unchanged\n' > "$tmp/sentinel"
cp "$tmp/sentinel" "$tmp/sentinel.expected"

# The historical implementation derived this public directory from its PID
# and followed a precreated text.txt symlink. A fresh Bash process has `$$`
# equal to the PID retained by exec, including on macOS Bash 3.2, so the test
# recreates that exact attack without guessing another process.
bash -c '
    set -e
    old_directory="/tmp/zupt_bench_corpus_$$"
    printf "%s\n" "$old_directory" > "$2/old-directory"
    mkdir "$old_directory"
    ln -s "$2/sentinel" "$old_directory/text.txt"
    test -L "$old_directory/text.txt"
    exec "$1" bench --compare >/dev/null 2>&1
' zupt-benchmark-test "$bin" "$tmp" || fail 'benchmark comparison failed'

cmp "$tmp/sentinel.expected" "$tmp/sentinel" ||
    fail 'benchmark followed the historical predictable temporary symlink'
old_directory=$(sed -n '1p' "$tmp/old-directory")
case $old_directory in
    /tmp/zupt_bench_corpus_[0-9]*) ;;
    *) fail 'unexpected historical temporary path' ;;
esac
if [[ -d $old_directory ]]; then
    mv "$old_directory" "$tmp/historical-remnant"
fi

# Inject a directory symlink into the private workspace while a real benchmark
# is active. Cleanup must remove the link itself and never visit its target.
mkdir "$tmp/symlink-target"
printf 'cleanup sentinel must survive\n' > "$tmp/symlink-target/sentinel"
cp "$tmp/symlink-target/sentinel" "$tmp/symlink-target.expected"
dd if=/dev/urandom of="$tmp/injection-input" bs=65536 count=128 2>/dev/null

physical_tmp=$(CDPATH='' cd -P -- /tmp && pwd -P)
: > "$tmp/preexisting-workspaces"
for candidate in "$physical_tmp"/zupt-bench-*; do
    if [[ -d $candidate && ! -L $candidate ]]; then
        printf '%s\n' "$candidate" >> "$tmp/preexisting-workspaces"
    fi
done

(cd "$tmp" && "$bin" bench injection-input >/dev/null 2>&1) &
bench_pid=$!
injected=0
injected_workspace=
attempt=0
while (( attempt < 1000 )); do
    for candidate in "$physical_tmp"/zupt-bench-*; do
        [[ -d $candidate && ! -L $candidate ]] || continue
        if grep -Fqx -- "$candidate" "$tmp/preexisting-workspaces"; then
            continue
        fi
        if ln -s "$tmp/symlink-target" "$candidate/attacker-link" \
                2>/dev/null; then
            injected=1
            injected_workspace=$candidate
            break
        fi
    done
    (( injected == 1 )) && break
    kill -0 "$bench_pid" 2>/dev/null || break
    sleep 0.01
    attempt=$((attempt + 1))
done
wait "$bench_pid" || fail 'benchmark with injected symlink failed'
(( injected == 1 )) || fail 'could not observe the private benchmark workspace'
if [[ -e $injected_workspace || -L $injected_workspace ]]; then
    fail 'injected workspace was not the benchmark tree that was removed'
fi
cmp "$tmp/symlink-target.expected" "$tmp/symlink-target/sentinel" ||
    fail 'temporary cleanup followed an injected directory symlink'

printf 'private descriptor/handle-relative benchmark workspace: PASS\n'
