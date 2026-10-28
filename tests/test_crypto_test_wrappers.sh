#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
set -euo pipefail

case ${1:-all} in
    all|status|flags) selection=${1:-all} ;;
    *) exit 2 ;;
esac
task_tmp=$(mktemp -d)
trap 'rm -rf -- "$task_tmp"' EXIT HUP INT TERM
failures=0

# These synthetic executables check shell orchestration only. The separate
# SHA-NI/HMAC targets must still compile and execute the real C fixtures.
wrapper_cc() {
    local output='' previous='' shani=0 compile=0 argument
    for argument in "$@"; do
        if [[ $previous == -o ]]; then output=$argument; fi
        [[ $argument != src/zupt_sha256_shani.c ]] || shani=1
        [[ $argument != -c ]] || compile=1
        previous=$argument
    done
    [[ -n $output ]] || return 41
    if [[ $WRAPPER_MODE == flags ]]; then
        case " $* " in *' -DZUPT_TEST_CPP_FLAGS '*) ;; *) return 42 ;; esac
        case " $* " in *' -DZUPT_TEST_C_FLAGS '*) ;; *) return 42 ;; esac
        case " $* " in *' -O2 '*) return 42 ;; esac
        if [[ $shani == 1 ]]; then
            [[ $compile == 1 ]] || return 42
            case " $* " in *' -DZUPT_TEST_SHANI_FLAGS '*) ;; *) return 42 ;; esac
        else
            case " $* " in
                *' -DZUPT_TEST_SHANI_FLAGS '*|*' -Wno-cast-align '*|*' -msha '*|*' -mssse3 '*|*' -msse4.1 '*) return 42 ;;
            esac
        fi
        if [[ $compile == 0 ]]; then
            case " $* " in *' -Wl,--as-needed '*) ;; *) return 42 ;; esac
            case " $* " in *' -pthread '*) ;; *) return 42 ;; esac
        fi
        printf '%s\n' "$shani:$compile" >> "$WRAPPER_TRACE"
    fi
    [[ $WRAPPER_MODE != compile-error ]] || return 43
    if [[ $compile == 1 ]]; then
        : > "$output"
        return 0
    fi
    if [[ $WRAPPER_MODE == skip || $WRAPPER_MODE == skip-error ]]; then
        printf '#!/bin/sh\nprintf "  SHA-NI: 0 passed, 0 failed (skipped)\\n"\n' > "$output"
    else
        printf '#!/bin/sh\nprintf "  SHA-NI: 4 passed, 0 failed\\n  Incremental HMAC: 1 passed, 0 failed\\n"\n' > "$output"
    fi
    if [[ $WRAPPER_MODE == signal ]]; then
        printf 'kill -TERM $$\n' >> "$output"
    else
        printf 'exit %s\n' "$WRAPPER_CHILD_STATUS" >> "$output"
    fi
    chmod 700 "$output"
}
gcc() {
    [[ $WRAPPER_MODE != flags ]] || return 44
    wrapper_cc "$@"
}
export -f wrapper_cc gcc

run_case() {
    local wrapper=$1 mode=$2 child_status=$3 expect_failure=$4 observed
    export WRAPPER_MODE=$mode WRAPPER_CHILD_STATUS=$child_status
    export WRAPPER_TRACE="$task_tmp/trace"
    : > "$WRAPPER_TRACE"
    if CC=wrapper_cc CPPFLAGS=-DZUPT_TEST_CPP_FLAGS \
        CFLAGS='-O0 -DZUPT_TEST_C_FLAGS' SHANI_CFLAGS='-Wno-cast-align -DZUPT_TEST_SHANI_FLAGS' \
        LDFLAGS=-Wl,--as-needed LDLIBS=-pthread \
        bash "tests/$wrapper.sh" > "$task_tmp/output" 2>&1; then
        observed=0
    else
        observed=$?
    fi
    if { [[ $expect_failure == 0 && $observed != 0 ]] ||
         [[ $expect_failure == 1 && $observed == 0 ]]; }; then
        sed 's/^/    /' "$task_tmp/output"
        printf 'FAIL: %s %s returned %s\n' "$wrapper" "$mode" "$observed" >&2
        failures=$((failures + 1))
        return
    fi
    if [[ $mode == flags ]] &&
       ! diff -u <(printf '1:1\n0:0\n') "$WRAPPER_TRACE"; then
        printf 'FAIL: %s did not isolate the SHA-NI object\n' "$wrapper" >&2
        failures=$((failures + 1))
        return
    fi
    printf 'PASS: %s %s shell fixture\n' "$wrapper" "$mode"
}

for wrapper in test_sha256_shani test_hmac_incremental; do
    if [[ $selection != flags ]]; then
        run_case "$wrapper" pass 0 0
        run_case "$wrapper" status-error 17 1
        run_case "$wrapper" signal 0 1
        run_case "$wrapper" compile-error 0 1
    fi
    if [[ $selection != status ]]; then run_case "$wrapper" flags 0 0; fi
done
if [[ $selection != flags ]]; then
    run_case test_sha256_shani skip 0 0
    run_case test_sha256_shani skip-error 17 1
fi

# These boundaries exercise the real ML-KEM shell supervisor, not cryptography.
# A producer that writes complete plausible output and then fails must fail it.
mlkem_fixture_key() { printf '%1184s' '' | tr ' ' K; }
mlkem_fixture_status() {
    printf '%s\n' "$1" >> "$MLKEM_TRACE"
    if [[ $MLKEM_CASE == "$1" ]]; then
        printf 'INJECTED_FAILURE %s 73\n' "$1" >> "$MLKEM_TRACE"
        return 73
    fi
}
openssl() {
    local stage=$1 output='' secret='' previous='' argument
    for argument in "$@"; do
        case $previous in -out) output=$argument ;; -secret) secret=$argument ;; esac
        previous=$argument
    done
    case $stage in
        version)
            case $MLKEM_CASE in
                legacy-1.1.1) printf 'OpenSSL 1.1.1w  11 Sep 2023\n' ;;
                legacy-3.0) printf 'OpenSSL 3.0.16  11 Feb 2025\n' ;;
                other-provider) printf 'LibreSSL 3.9.2\n' ;;
                *) printf 'OpenSSL 3.5.7 synthetic fixture\n' ;;
            esac ;;
        list)
            [[ ${2:-} == -kem-algorithms ]] || return 41
            case $MLKEM_CASE in
                legacy-*|other-provider)
                    printf 'openssl-list\n' >> "$MLKEM_TRACE"
                    printf 'unsupported synthetic list option\n' >&2
                    return 1 ;;
                mixed-case) printf 'mL-kEm-768\n' ;;
                *) printf 'ML-KEM-768\n' ;;
            esac ;;
        genpkey) printf 'synthetic private key\n' > "$output" ;;
        pkey) { printf 'synthetic DER header'; mlkem_fixture_key; } > "$output" ;;
        pkeyutl)
            stage=${2#-}
            case $stage in
                decap) printf 'shared secret\n' > "$secret" ;;
                encap)
                    printf 'shared secret\n' > "$secret"
                    printf 'ciphertext\n' > "$output" ;;
                *) return 41 ;;
            esac ;;
        *) return 41 ;;
    esac
    mlkem_fixture_status "openssl-$stage"
}
mlkem_fixture_harness() {
    local stage=$1
    case $stage in
        keygen)
            stage=first-keygen
            if [[ -e $MLKEM_CASE_DIR/keygen ]]; then stage=second-keygen; fi
            : > "$MLKEM_CASE_DIR/keygen"
            mlkem_fixture_key > ek.bin
            printf 'synthetic private key\n' > dk.bin ;;
        encaps)
            printf 'ciphertext\n' > ct.bin
            printf 'shared secret\n' > ss.bin ;;
        decaps) printf 'shared secret\n' > ss.bin ;;
        *) return 41 ;;
    esac
    mlkem_fixture_status "harness-$stage"
}
mlkem_fixture_cc() {
    local output='' previous='' argument
    printf 'compiler\n' >> "$MLKEM_TRACE"
    for argument in "$@"; do
        [[ $previous != -o ]] || output=$argument
        previous=$argument
    done
    [[ -n $output ]] || return 41
    printf '#!%s\nmlkem_fixture_harness "$@"\n' "$BASH" > "$output"
    chmod 700 "$output"
}

if [[ $selection != flags ]]; then
    export -f mlkem_fixture_key mlkem_fixture_status openssl \
        mlkem_fixture_harness mlkem_fixture_cc
    for boundary in clean mixed-case legacy-1.1.1 legacy-3.0 other-provider \
        openssl-version openssl-list openssl-genpkey openssl-pkey openssl-decap \
        openssl-encap harness-first-keygen harness-encaps harness-second-keygen harness-decaps; do
        export MLKEM_CASE=$boundary MLKEM_CASE_DIR="$task_tmp/$boundary"
        mkdir "$MLKEM_CASE_DIR"
        export MLKEM_TRACE="$MLKEM_CASE_DIR/trace"
        : > "$MLKEM_TRACE"
        observed=0
        CC=mlkem_fixture_cc bash tests/test_mlkem_fips203.sh \
            > "$MLKEM_CASE_DIR/output" 2>&1 || observed=$?
        if [[ $boundary == clean || $boundary == mixed-case ]]; then
            if [[ $observed == 0 ]] &&
               grep -Fxq '  Conformance: 3 passed, 0 failed' "$MLKEM_CASE_DIR/output"; then
                printf 'PASS: ML-KEM %s synthetic shell flow (not crypto proof)\n' "$boundary"
                continue
            fi
        elif [[ $boundary == legacy-* || $boundary == other-provider ]]; then
            if [[ $observed == 0 && $(< "$MLKEM_TRACE") == openssl-version ]] &&
               grep -Eq '^  SKIP:' "$MLKEM_CASE_DIR/output"; then
                printf 'PASS: ML-KEM skips synthetic %s before query or compile\n' "$boundary"
                continue
            fi
        elif [[ $observed != 0 ]] &&
             grep -Fxq "INJECTED_FAILURE $boundary 73" "$MLKEM_TRACE"; then
            printf 'PASS: ML-KEM rejects synthetic %s producer failure\n' "$boundary"
            continue
        fi
        sed 's/^/    /' "$MLKEM_CASE_DIR/output" "$MLKEM_TRACE"
        printf 'FAIL: ML-KEM synthetic %s returned %s\n' "$boundary" "$observed" >&2
        failures=$((failures + 1))
    done
fi
[[ $failures == 0 ]]
