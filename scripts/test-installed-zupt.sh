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

show_cli_log() {
    printf 'CLI status: %s (expected %s): %s\n' "$2" "$3" "$(basename -- "$1")"
    cat -- "$1"
}

# A parser rejection is not a crash or a sanitizer finding. Inspect the
# combined output even when the process returns its expected status.
run_cli() {
    local expected=$1 log=$2 diagnostic=$3 status scan_status
    shift 3
    if "$@" > "$log" 2>&1; then
        status=0
    else
        status=$?
    fi
    if grep -aEq 'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:' "$log"; then
        show_cli_log "$log" "$status" "$expected"
        die 'CLI emitted a sanitizer diagnostic'
    else
        scan_status=$?
        if [[ $scan_status != 1 ]]; then
            show_cli_log "$log" "$status" "$expected"
            die 'cannot inspect CLI diagnostic log'
        fi
    fi
    if [[ $status != "$expected" ]]; then
        show_cli_log "$log" "$status" "$expected"
        die "unexpected CLI status: $status (expected $expected)"
    fi
    if [[ -n $diagnostic ]] && ! grep -aFq -- "$diagnostic" "$log"; then
        show_cli_log "$log" "$status" "$expected"
        die 'CLI rejection did not contain the expected diagnostic'
    fi
    if [[ $expected != 0 ]]; then
        show_cli_log "$log" "$status" "$expected"
    fi
}

hash_tree() {
    local tree=$1
    (
        cd -- "$tree" || exit
        if command -v sha256sum >/dev/null 2>&1; then
            find . -type f -exec sha256sum {} + | LC_ALL=C sort
        elif command -v shasum >/dev/null 2>&1; then
            find . -type f -exec shasum -a 256 {} + | LC_ALL=C sort
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

run_cli 0 "$test_root/version.log" '' "$binary" --version
grep -q '^zupt ' "$test_root/version.log" || {
    show_cli_log "$test_root/version.log" 0 0
    die '--version did not identify zupt'
}
pass '--version'

run_cli 0 "$test_root/help.log" '' "$binary" --help
grep -q '^Usage:' "$test_root/help.log" || {
    show_cli_log "$test_root/help.log" 0 0
    die '--help did not contain Usage'
}
pass '--help'

run_cli 1 "$test_root/invalid.log" \
    "Unknown command '--definitely-invalid-option'. Run 'zupt help'." \
    "$binary" --definitely-invalid-option
pass 'invalid option returns failure'

plain_archive=$test_root/plain.zupt
run_cli 0 "$test_root/plain-compress.log" '' "$binary" compress "$plain_archive" "$input"
run_cli 0 "$test_root/plain-test.log" '' "$binary" test "$plain_archive"
run_cli 0 "$test_root/plain-extract.log" '' "$binary" extract -o "$plain_out" "$plain_archive"
extracted_markers=()
while IFS= read -r -d '' marker; do
    extracted_markers[${#extracted_markers[@]}]=$marker
done < <(find "$plain_out" -type f -name 'text file.txt' -print0)
[[ ${#extracted_markers[@]} -eq 1 ]] || die 'extracted tree is missing or ambiguous'
extracted_input=$(dirname -- "${extracted_markers[0]}")
[[ -f $extracted_input/subdir/café-安全.txt && -f $extracted_input/empty\ file ]] || \
    die 'extracted tree is incomplete'
diff -r -- "$input" "$extracted_input" > "$test_root/plain-diff.log" || die 'plain round-trip differs'

hash_tree "$input" > "$test_root/original.sha256" || die 'cannot hash input tree'
hash_tree "$extracted_input" > "$test_root/extracted.sha256" || die 'cannot hash extracted tree'
cmp -- "$test_root/original.sha256" "$test_root/extracted.sha256" || die 'round-trip SHA-256 manifests differ'
pass 'text, random, empty, nested, spaces and UTF-8 round-trip'

password='ZUPT-test-password-2026!'
password_archive=$test_root/password.zupt
run_cli 0 "$test_root/password-compress.log" '' "$binary" compress -p "$password" "$password_archive" "$input/text file.txt"
run_cli 0 "$test_root/password-test.log" '' "$binary" test -p "$password" "$password_archive"
run_cli 0 "$test_root/password-extract.log" '' "$binary" extract -p "$password" -o "$password_out" "$password_archive"
password_markers=()
while IFS= read -r -d '' marker; do
    password_markers[${#password_markers[@]}]=$marker
done < <(find "$password_out" -type f -name 'text file.txt' -print0)
[[ ${#password_markers[@]} -eq 1 ]] || die 'password extraction is missing or ambiguous'
cmp -- "$input/text file.txt" "${password_markers[0]}" || die 'password round-trip differs'
run_cli 1 "$test_root/wrong-password.log" 'Error: Authentication failed' \
    "$binary" extract -p 'incorrect-password' -o "$test_root/wrong-password-out" "$password_archive"
pass 'password round-trip and incorrect-password rejection'

archive_size=$(wc -c < "$plain_archive")
(( archive_size > 32 )) || die 'archive unexpectedly small'
head -c "$((archive_size - 17))" "$plain_archive" > "$test_root/corrupt.zupt"
run_cli 1 "$test_root/corrupt.log" 'Error: Archive is corrupt' \
    "$binary" test "$test_root/corrupt.zupt"
pass 'corrupt archive rejection'

archive_input_rel=${extracted_input#"$plain_out"/}
[[ $archive_input_rel != "$extracted_input" && $archive_input_rel != /* ]] || \
    die 'cannot determine the archive extraction path'
mkdir -p -- "$escape_out/$(dirname -- "$archive_input_rel")"
ln -s -- "$outside" "$escape_out/$archive_input_rel"
run_cli 1 "$test_root/escape.log" 'Error: cannot create ' \
    "$binary" extract -o "$escape_out" "$plain_archive"
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
