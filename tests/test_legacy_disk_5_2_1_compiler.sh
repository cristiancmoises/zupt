#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-legacy-compiler.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
export LEGACY_CONTROL_LIBRARY=$test_tmp/control.a
printf '!<arch>\n' > "$LEGACY_CONTROL_LIBRARY"

# Exercise the real script; a controlled compiler failure stops before any CLI.
cat > "$test_tmp/compiler" <<'SH'
#!/usr/bin/env bash
set -eu
: > "$LEGACY_CONTROL_CALLED"
if [[ $LEGACY_CONTROL_MODE == multiword ]]; then
    [[ $1 == --compiler-prefix ]] || exit 92
    shift
fi
output='' source='' previous=''
for argument in "$@"; do
    [[ -n $argument ]] || exit 93
    [[ $previous != -o ]] || output=$argument
    case $argument in */fixture_hex_decode.c) source=$argument ;; esac
    case $argument in
        "$LEGACY_CONTROL_LIBRARY"|-static|-Wl,--build-id=none) [[ -n $source ]] || exit 97 ;;
    esac
    previous=$argument
done
[[ -n $output && -r $source ]] || exit 94
if [[ $LEGACY_CONTROL_MODE == unset_flags || $LEGACY_CONTROL_MODE == empty_flags ]]; then
    [[ $# == 7 ]] || exit 95
    required=(-std=c11 -Wall -Wextra -Werror)
else
    required=(-std=c11 -Wall -Wextra -Werror -DLEGACY_CPP_CONTROL=1
        -O0 -g -DLEGACY_C_CONTROL=1 -static -Wl,--build-id=none
        "$LEGACY_CONTROL_LIBRARY" -lm)
fi
for expected in "${required[@]}"; do
    found=0
    for argument in "$@"; do [[ $argument != "$expected" ]] || found=1; done
    if [[ $found != 1 ]]; then
        printf 'control compiler missing flag: %s\n' "$expected" >&2
        exit 42
    fi
done
echo 'control compiler diagnostic (exit 41)' >&2
exit 41
SH
chmod 700 "$test_tmp/compiler"

failures=0
for mode in flags multiword unset_flags empty_flags; do
    control_cc=$test_tmp/compiler
    [[ $mode != multiword ]] || control_cc="bash $test_tmp/compiler --compiler-prefix"
    control_env=(CPPFLAGS=-DLEGACY_CPP_CONTROL=1 'CFLAGS=-O0 -g -DLEGACY_C_CONTROL=1'
        'LDFLAGS=-static -Wl,--build-id=none' "LDLIBS=$LEGACY_CONTROL_LIBRARY -lm")
    if [[ $mode == unset_flags ]]; then
        control_env=(-u CPPFLAGS -u CFLAGS -u LDFLAGS -u LDLIBS)
    elif [[ $mode == empty_flags ]]; then
        control_env=(CPPFLAGS= CFLAGS= LDFLAGS= LDLIBS=)
    fi
    if env "${control_env[@]}" LEGACY_CONTROL_MODE="$mode" CC="$control_cc" \
        LEGACY_CONTROL_CALLED="$test_tmp/$mode.called" \
        bash "$repo_root/tests/test_legacy_disk_5_2_1.sh" "$test_tmp/CLI-MUST-NOT-RUN" \
            > "$test_tmp/$mode.log" 2>&1; then
        status=0
    else
        status=$?
    fi
    if [[ $status != 41 || ! -f $test_tmp/$mode.called ]] || \
        ! grep -aFq 'control compiler diagnostic (exit 41)' "$test_tmp/$mode.log"; then
        cat "$test_tmp/$mode.log" >&2
        printf 'FAIL: legacy fixture compiler %s returned %s or hid its diagnostic (expected 41)\n' \
            "$mode" "$status" >&2
        failures=$((failures + 1))
        continue
    fi
    printf 'PASS: legacy fixture compiler %s (exit 41; CLI not invoked)\n' "$mode"
done
[[ $failures == 0 ]]
