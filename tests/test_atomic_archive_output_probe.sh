#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
bin=${1:-./zupt}
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-atomic-probe-controls.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
export PROBE_CONTROL_RUNNER=$test_tmp/runner
export PROBE_CONTROL_LIBRARY=$test_tmp/control.a
printf '!<arch>\n' > "$PROBE_CONTROL_LIBRARY"

# Mock only the compiler/probe boundary; never replace the product CLI.
cat > "$test_tmp/compiler" <<'SH'
#!/usr/bin/env bash
set -eu
[[ $1 == --compiler-prefix ]] || exit 92
shift
output='' source='' previous=''
for argument in "$@"; do
    [[ $previous != -o ]] || output=$argument
    case $argument in */search-only-open-probe.c) source=$argument ;; esac
    previous=$argument
done
[[ -n $output ]] || exit 93
[[ -r $source ]] || exit 94
if [[ $PROBE_CONTROL_MODE == empty_flags ]]; then
    [[ $# == 7 ]] || exit 95
    for argument in "$@"; do [[ -n $argument ]] || exit 96; done
fi
if [[ $PROBE_CONTROL_MODE == flags ]]; then
    for required in -DPROBE_CPP_CONTROL -DPROBE_C_CONTROL -O0 -Wl,--as-needed "$PROBE_CONTROL_LIBRARY" -lm; do
        found=0
        for argument in "$@"; do [[ $argument != "$required" ]] || found=1; done
        if [[ $found != 1 ]]; then
            printf 'control compiler missing flag: %s\n' "$required" >&2
            exit 42
        fi
    done
fi
if [[ $PROBE_CONTROL_MODE == compile_failure ]]; then
    echo 'control compiler diagnostic' >&2
    exit 41
fi
cp "$PROBE_CONTROL_RUNNER" "$output"
chmod 700 "$output"
if [[ $PROBE_CONTROL_MODE == compile_sanitizer ]]; then
    echo 'runtime error: compiler control diagnostic' >&2
fi
SH
cat > "$test_tmp/runner" <<'SH'
#!/usr/bin/env bash
set -eu
case $PROBE_CONTROL_MODE in
    unsupported) echo 'search-only directory capability: unsupported'; exit 1 ;;
    runtime_failure) echo 'control probe runtime diagnostic' >&2; exit 29 ;;
    runtime_exit_one) echo 'control probe runtime diagnostic' >&2; exit 1 ;;
    runtime_sanitizer_one)
        echo 'runtime error: probe control diagnostic' >&2
        echo 'search-only directory capability: unsupported'; exit 1 ;;
    address) echo 'AddressSanitizer: probe control diagnostic' >&2 ;;
    leak) echo 'LeakSanitizer: probe control diagnostic' >&2 ;;
    undefined) echo 'UndefinedBehaviorSanitizer: probe control diagnostic' >&2 ;;
    runtime_error) echo 'runtime error: probe control diagnostic' >&2 ;;
    missing_marker) exit 1 ;;
    mismatched_marker) echo 'search-only directory capability: unsupported'; exit 0 ;;
    duplicate_marker) echo 'search-only directory capability: supported' ;;
    contradictory_markers) echo 'search-only directory capability: unsupported' ;;
esac
echo 'search-only directory capability: supported'
SH

failures=0
for control in flags:0 empty_flags:0 unsupported:1 compile_failure:41 compile_sanitizer:2 \
    runtime_failure:29 runtime_exit_one:2 runtime_sanitizer_one:2 \
    address:2 leak:2 undefined:2 runtime_error:2 \
    missing_marker:2 mismatched_marker:2 duplicate_marker:2 contradictory_markers:2; do
    mode=${control%:*}
    expected=${control#*:}
    control_env=(CPPFLAGS=-DPROBE_CPP_CONTROL 'CFLAGS=-O0 -DPROBE_C_CONTROL'
        LDFLAGS=-Wl,--as-needed "LDLIBS=$PROBE_CONTROL_LIBRARY -lm")
    if [[ $mode == empty_flags ]]; then
        control_env=(-u CPPFLAGS -u CFLAGS -u LDFLAGS -u LDLIBS)
    fi
    if env "${control_env[@]}" PROBE_CONTROL_MODE="$mode" \
        CC="bash $test_tmp/compiler --compiler-prefix" \
        bash "$repo_root/tests/test_atomic_archive_output.sh" "$bin" --probe-only \
            > "$test_tmp/$mode.log" 2>&1; then
        status=0
    else
        status=$?
    fi
    if [[ $status != "$expected" ]]; then
        cat "$test_tmp/$mode.log" >&2
        printf 'FAIL: atomic probe %s returned %s (expected %s)\n' \
            "$mode" "$status" "$expected" >&2
        failures=$((failures + 1))
        continue
    fi
    case $mode in
        compile_failure) diagnostic='control compiler diagnostic' ;;
        runtime_failure|runtime_exit_one) diagnostic='control probe runtime diagnostic' ;;
        *) diagnostic='' ;;
    esac
    if [[ -n $diagnostic ]] && ! grep -aFq "$diagnostic" "$test_tmp/$mode.log"; then
        cat "$test_tmp/$mode.log" >&2
        printf 'FAIL: atomic probe %s hid the diagnostic\n' "$mode" >&2
        failures=$((failures + 1))
        continue
    fi
    printf 'PASS: atomic probe %s (exit %s)\n' "$mode" "$status"
done
[[ $failures == 0 ]]
