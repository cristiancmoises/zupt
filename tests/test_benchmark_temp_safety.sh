#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

bin=${1:-./zupt}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-bench-safety.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

case $(uname -s 2>/dev/null || printf unknown) in
    MINGW*|MSYS*|CYGWIN*)
        printf 'SKIP: historical POSIX /tmp symlink benchmark test is not native on Windows\n'
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

printf 'private benchmark workspace: PASS\n'
