#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Selected Jasmin source analysis and generated AES behavior, not a full audit.
set -eu
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
jasminc=${JASMINC:-jasminc}
jasmin_ct=${JASMIN_CT:-jasmin-ct}
jasmin_safety=${JASMIN_SAFETY:-jasmin-checksafety}
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-jasmin-source.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

run_check() {
    label=$1
    shift
    printf 'Running: %s\n' "$label"
    if "$@" >"$test_tmp/$label.log" 2>&1; then
        cat "$test_tmp/$label.log"
    else
        status=$?
        cat "$test_tmp/$label.log"
        printf 'FAIL: %s exited %s\n' "$label" "$status" >&2
        exit "$status"
    fi
    warning_status=0
    grep -Eiq '(^|[[:space:]])warning(:|[[:space:]])' "$test_tmp/$label.log" || warning_status=$?
    case "$warning_status" in
        0)
            printf 'FAIL: %s emitted a warning\n' "$label" >&2
            exit 1 ;;
        1) ;;
        *)
            printf 'FAIL: %s warning scan exited %s\n' "$label" "$warning_status" >&2
            exit "$warning_status" ;;
    esac
}

check_version() {
    version=$("$1" "$2")
    if [ "$version" != 'Jasmin Compiler 2026.09.0' ]; then
        printf 'FAIL: this source gate requires Jasmin 2026.09.0, got %s\n' "$version" >&2
        exit 1
    fi
    printf '%s\n' "$version"
}
check_version "$jasminc" -version
check_version "$jasmin_ct" --version
check_version "$jasmin_safety" --version

check_export() {
    unit=$1
    artifact=$2
    symbol=$3
    run_check "$unit-$artifact-sections" env LC_ALL=C "${READELF:-readelf}" \
        --wide --section-headers "$test_tmp/$unit-$artifact.o"
    text_section=$(awk '
        /^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]+\.text[[:space:]]/ {
            line = $0
            sub(/^[[:space:]]*\[[[:space:]]*/, "", line)
            sub(/\].*$/, "", line)
            print line
            ++count
        }
        END { if (count != 1) exit 1 }
    ' "$test_tmp/$unit-$artifact-sections.log")
    run_check "$unit-$artifact-symbols" env LC_ALL=C "${READELF:-readelf}" \
        --wide --symbols "$test_tmp/$unit-$artifact.o"
    # One exported function must start at the compared instruction section.
    # This checks name/binding/type/placement, not the C argument contract.
    awk -v wanted="$symbol" -v section="$text_section" '
        $4 == "FUNC" && $5 == "GLOBAL" {
            ++count
            if ($8 != wanted || $6 != "DEFAULT" || $7 != section || $2 !~ /^0+$/)
                invalid = 1
        }
        END {
            if (count != 1 || invalid) {
                print "FAIL: object does not define the expected exported function " wanted
                exit 1
            }
        }
    ' "$test_tmp/$unit-$artifact-symbols.log"
}

for unit in zupt_aes_ctr zupt_aes_ctr4 zupt_mac_verify zupt_mlkem_select zupt_x25519_fe; do
    source_file="$repo_root/jasmin/$unit.jazz"
    case "$unit" in
        zupt_aes_ctr) symbol=zupt_aes256_blk ;;
        zupt_aes_ctr4) symbol=zupt_aes256_ctr4 ;;
        zupt_mac_verify) symbol=zupt_mac_verify_ct ;;
        zupt_mlkem_select) symbol=zupt_ct_select_32 ;;
        zupt_x25519_fe) symbol=zupt_fe_cswap ;;
    esac
    run_check "$unit-compile" "$jasminc" -wall -o "$test_tmp/$unit.s" "$source_file"
    test -s "$test_tmp/$unit.s"
    # shellcheck disable=SC2086
    run_check "$unit-generated-object" "${CC:-cc}" ${ASFLAGS:-} \
        -c "$test_tmp/$unit.s" -o "$test_tmp/$unit-generated.o"
    check_export "$unit" generated "$symbol"
    if [ "$unit" = zupt_aes_ctr4 ]; then
        # Declare the actual pointer/count roles for the variable-length ABI.
        # Allocation ranges remain conditional caller obligations.
        run_check "$unit-safety" "$jasmin_safety" --arch=x86-64 \
            --param 'zupt_aes256_ctr4>out_ptr,in_ptr,key_ptr,ctr_ptr;nblocks' "$source_file"
    else
        run_check "$unit-safety" "$jasmin_safety" --arch=x86-64 "$source_file"
    fi
    grep -Fq '*** No Safety Violation' "$test_tmp/$unit-safety.log"
    run_check "$unit-ct" "$jasmin_ct" --arch=x86-64 --print "$source_file"
    run_check "$unit-doit" "$jasmin_ct" --arch=x86-64 --doit --warn --print "$source_file"
    run_check "$unit-lowering-doit" "$jasmin_ct" --arch=x86-64 \
        --compile=lowering --doit --warn --print "$source_file"
    # These leaves have no relocations. Instruction bytes alone would not
    # compare external-symbol references, so reject that unsupported case.
    # shellcheck disable=SC2086
    run_check "$unit-runtime-object" "${CC:-cc}" ${ASFLAGS:-} \
        -c "$repo_root/jasmin/$unit.s" -o "$test_tmp/$unit-runtime.o"
    check_export "$unit" runtime "$symbol"
    for artifact in generated runtime; do
        run_check "$unit-$artifact-relocations" env LC_ALL=C \
            "${READELF:-readelf}" --relocs "$test_tmp/$unit-$artifact.o"
        if ! grep -Fxq 'There are no relocations in this file.' \
                "$test_tmp/$unit-$artifact-relocations.log"; then
            printf 'FAIL: %s %s object has relocations; instruction-only comparison is insufficient\n' \
                "$unit" "$artifact" >&2
            exit 1
        fi
    done
    # Comments and provenance headers need not be identical. Compare the
    # actual instructions assembled by the selected driver for both sources.
    "${OBJCOPY:-objcopy}" --only-section=.text -O binary \
        "$test_tmp/$unit-generated.o" "$test_tmp/$unit-generated.text"
    "${OBJCOPY:-objcopy}" --only-section=.text -O binary \
        "$test_tmp/$unit-runtime.o" "$test_tmp/$unit-runtime.text"
    test -s "$test_tmp/$unit-generated.text"
    comparison_status=0
    cmp -s "$test_tmp/$unit-generated.text" "$test_tmp/$unit-runtime.text" || comparison_status=$?
    case "$comparison_status" in
        0) ;;
        1)
            printf 'FAIL: %s runtime instructions differ from regenerated source\n' "$unit" >&2
            exit 1 ;;
        *)
            printf 'FAIL: %s instruction comparison could not run (status %s)\n' \
                "$unit" "$comparison_status" >&2
            exit "$comparison_status" ;;
    esac
    printf 'PASS: %s generated/runtime instruction bytes match\n' "$unit"
done

# Pin the observed compiler's wipe pattern, including every round-key slot.
# This checks emitted stores, not register erasure or compiler correctness.
for unit in zupt_aes_ctr zupt_aes_ctr4; do
    slots=15
    if [ "$unit" = zupt_aes_ctr4 ]; then slots=16; fi
    awk -v slots="$slots" -f "$repo_root/tests/check_jasmin_wipe.awk" \
        "$test_tmp/$unit.s"
done

crypto_cflags=$("${PKG_CONFIG:-pkg-config}" --cflags libcrypto)
crypto_libs=$("${PKG_CONFIG:-pkg-config}" --libs libcrypto)
# Flag lists intentionally follow Make's whitespace splitting; CC is a driver.
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g} $crypto_cflags \
    -std=c11 -Wall -Wextra -Werror -Wconversion -Wshadow -Wstrict-prototypes \
    "$repo_root/tests/test_jasmin_aes_block.c" "$test_tmp/zupt_aes_ctr.s" \
    ${LDFLAGS:-} -Wl,-z,noexecstack $crypto_libs ${LDLIBS:-} \
    -o "$test_tmp/aes-block"
run_check aes-block "$test_tmp/aes-block"
grep -Fq 'Summary: failed_groups=0 total_blocks=1026 seed=0x4a534d49' \
    "$test_tmp/aes-block.log"
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:--O2 -g} $crypto_cflags \
    -std=c11 -Wall -Wextra -Werror -Wconversion -Wshadow -Wstrict-prototypes \
    "$repo_root/tests/test_jasmin_aes_ctr4.c" "$test_tmp/zupt_aes_ctr4.s" \
    ${LDFLAGS:-} -Wl,-z,noexecstack $crypto_libs ${LDLIBS:-} \
    -o "$test_tmp/aes-ctr4"
run_check aes-ctr4 "$test_tmp/aes-ctr4"
grep -Fq 'Summary: failures=0 total_cases=1539 seed=0x43545234' \
    "$test_tmp/aes-ctr4.log"
printf 'PASS: five selected Jasmin sources and generated AES fixtures\n'
printf 'LIMIT: caller preconditions apply; final packaged binaries are not checked\n'
