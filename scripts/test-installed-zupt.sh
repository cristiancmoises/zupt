#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

set -Eeuo pipefail

umask 077
export LC_ALL=C

die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

pass() {
    printf 'PASS: %s\n' "$1"
}

hash_tree() {
    local tree=$1
    (
        cd -- "$tree"
        if command -v sha256sum >/dev/null 2>&1; then
            find . -type f -exec sha256sum {} \; | LC_ALL=C sort
        elif command -v shasum >/dev/null 2>&1; then
            find . -type f -exec shasum -a 256 {} \; | LC_ALL=C sort
        else
            die 'sha256sum or shasum is required'
        fi
    )
}

# ZUPT_BIN is the public override. VAPTVUPT_BIN remains a compatibility
# fallback for existing automation during the package-name transition.
candidate=${1:-${ZUPT_BIN:-${VAPTVUPT_BIN:-zupt}}}
if [[ $candidate == */* ]]; then
    [[ -x $candidate ]] || die "executable not found: $candidate"
    binary=$(cd -- "$(dirname -- "$candidate")" && pwd -P)/$(basename -- "$candidate")
else
    binary=$(command -v -- "$candidate" || true)
    [[ -n $binary ]] || die "executable not found on PATH: $candidate"
fi

test_root=$(mktemp -d "${TMPDIR:-/tmp}/zupt-installed.XXXXXX")
trap 'chmod -R u+rwX "$test_root" 2>/dev/null || true; rm -rf -- "$test_root"' EXIT HUP INT TERM

input=$test_root/input
plain_out=$test_root/plain-out
password_out=$test_root/password-out
escape_out=$test_root/escape-out
outside=$test_root/outside
mkdir -p "$input/subdir" "$plain_out" "$password_out" "$escape_out" "$outside"

printf 'ZUPT installed smoke test\nsecond line\n' > "$input/text file.txt"
printf 'conteúdo UTF-8\n' > "$input/subdir/café-安全.txt"
: > "$input/empty file"
dd if=/dev/urandom of="$input/subdir/random.bin" bs=4096 count=8 2>/dev/null
printf 'do-not-overwrite\n' > "$outside/sentinel"

"$binary" --version > "$test_root/version.log" 2>&1
grep -q '^zupt ' "$test_root/version.log" || die "--version did not identify zupt"
pass '--version'

"$binary" --help > "$test_root/help.log" 2>&1
grep -q '^Usage:' "$test_root/help.log" || die "--help did not contain Usage"
pass '--help'

if "$binary" --definitely-invalid-option > "$test_root/invalid.log" 2>&1; then
    die 'invalid option returned success'
fi
pass 'invalid option returns failure'

plain_archive=$test_root/plain.zupt
"$binary" compress "$plain_archive" "$input" > "$test_root/plain-compress.log" 2>&1
"$binary" test "$plain_archive" > "$test_root/plain-test.log" 2>&1
"$binary" extract -o "$plain_out" "$plain_archive" > "$test_root/plain-extract.log" 2>&1
extracted_markers=()
while IFS= read -r -d '' marker; do
    extracted_markers[${#extracted_markers[@]}]=$marker
done < <(find "$plain_out" -type f -name 'text file.txt' -print0)
[[ ${#extracted_markers[@]} -eq 1 ]] || die 'extracted tree is missing or ambiguous'
extracted_input=$(dirname -- "${extracted_markers[0]}")
[[ -f $extracted_input/subdir/café-安全.txt && -f $extracted_input/empty\ file ]] || \
    die 'extracted tree is incomplete'
diff -r -- "$input" "$extracted_input" > "$test_root/plain-diff.log" || die 'plain round-trip differs'

hash_tree "$input" > "$test_root/original.sha256"
hash_tree "$extracted_input" > "$test_root/extracted.sha256"
cmp -- "$test_root/original.sha256" "$test_root/extracted.sha256" || die 'round-trip SHA-256 manifests differ'
pass 'text, random, empty, nested, spaces and UTF-8 round-trip'

password='ZUPT-test-password-2026!'
password_archive=$test_root/password.zupt
"$binary" compress -p "$password" "$password_archive" "$input/text file.txt" > "$test_root/password-compress.log" 2>&1
"$binary" test -p "$password" "$password_archive" > "$test_root/password-test.log" 2>&1
"$binary" extract -p "$password" -o "$password_out" "$password_archive" > "$test_root/password-extract.log" 2>&1
password_markers=()
while IFS= read -r -d '' marker; do
    password_markers[${#password_markers[@]}]=$marker
done < <(find "$password_out" -type f -name 'text file.txt' -print0)
[[ ${#password_markers[@]} -eq 1 ]] || die 'password extraction is missing or ambiguous'
cmp -- "$input/text file.txt" "${password_markers[0]}" || die 'password round-trip differs'
if "$binary" extract -p 'incorrect-password' -o "$test_root/wrong-password-out" "$password_archive" > "$test_root/wrong-password.log" 2>&1; then
    die 'incorrect password returned success'
fi
pass 'password round-trip and incorrect-password rejection'

archive_size=$(wc -c < "$plain_archive")
(( archive_size > 32 )) || die 'archive unexpectedly small'
head -c "$((archive_size - 17))" "$plain_archive" > "$test_root/corrupt.zupt"
if "$binary" test "$test_root/corrupt.zupt" > "$test_root/corrupt.log" 2>&1; then
    die 'truncated archive returned success'
fi
pass 'corrupt archive rejection'

archive_input_rel=${extracted_input#"$plain_out"/}
[[ $archive_input_rel != "$extracted_input" && $archive_input_rel != /* ]] || \
    die 'cannot determine the archive extraction path'
mkdir -p -- "$escape_out/$(dirname -- "$archive_input_rel")"
ln -s -- "$outside" "$escape_out/$archive_input_rel"
"$binary" extract -o "$escape_out" "$plain_archive" > "$test_root/escape.log" 2>&1 || true
[[ $(<"$outside/sentinel") == 'do-not-overwrite' ]] || die 'extraction overwrote outside sentinel'
[[ ! -e "$outside/text file.txt" && ! -e "$outside/subdir" ]] || die 'extraction escaped through a destination symlink'
pass 'no write outside extraction destination'

if [[ $(id -u) -eq 0 ]]; then
    printf 'SKIP: unprivileged execution (test process is root)\n'
else
    [[ -r $plain_archive && -x $binary ]] || die 'unprivileged process cannot read archive or execute binary'
    pass 'execution as an unprivileged user'
fi

printf 'PASS: installed ZUPT functional test suite\n'
