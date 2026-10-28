#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Static-analysis regression for v3.0.3.
#
# Asserts that every first-party src/zupt_*.c translation unit compiles under:
#   - GCC strict warnings + -Werror
#   - GCC -Wconversion + -Wsign-conversion on the security/I/O subset where
#     that warning policy is already clean
#   - cppcheck warning + performance level
#
# History:
#   F-13 (v3.0.2): -Woverlength-strings on usage() literal
#   (v3.0.3): Two -Wconversion warnings (ECHO bit-clear, varint return).
#             Two `knownConditionTrueFalse` cppcheck findings in varint
#             decoders (dead AND-branch after early return).
# This test guards against regressions of all four classes.

set -u
PASS=0; FAIL=0
STATIC_CC=${CC:-gcc}
P() { echo "  ✓ $1"; PASS=$((PASS+1)); }
F() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

STATIC_TMP=$(mktemp -d "${TMPDIR:-/tmp}/zupt-static-analysis.XXXXXXXX") || exit 1
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$STATIC_TMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

# grep uses status 1 for a valid no-match result, not for a tool/read error.
checked_grep() {
    local grep_status
    if grep "$@"; then
        return 0
    else
        grep_status=$?
    fi
    if [ "$grep_status" -eq 1 ]; then
        return 1
    fi
    F "grep exited with status $grep_status" >&2
    exit 1
}

# Keep the count in n without a subshell around this function: an invalid
# producer result must stop the gate, including when it already printed zero.
count_findings() {
    local grep_status
    if n=$(grep "$@"); then
        grep_status=0
    else
        grep_status=$?
    fi
    case "$grep_status" in
        0|1) ;;
        *) F "grep count exited with status $grep_status" >&2; exit 1 ;;
    esac
    case "$n" in
        0) [ "$grep_status" -eq 1 ] && return ;;
        ''|0*|*[!0-9]*) ;;
        *) [ "$grep_status" -eq 0 ] && return ;;
    esac
    F "grep returned an invalid or inconsistent count" >&2
    exit 1
}

# Derive the list so a newly added first-party translation unit cannot silently
# escape this gate.  Bundled GPL codec sources use their own warning policy.
OUR_FILES=()
if find src -maxdepth 1 -type f -name 'zupt_*.c' \
        ! -name 'zupt_sha256_shani.c' -print0 > "$STATIC_TMP/sources.unsorted"; then
    :
else
    discovery_status=$?
    F "source discovery find exited with status $discovery_status"
    exit 1
fi
if sort -z "$STATIC_TMP/sources.unsorted" > "$STATIC_TMP/sources.sorted"; then
    :
else
    discovery_status=$?
    F "source discovery sort exited with status $discovery_status"
    exit 1
fi
while IFS= read -r -d '' source_file; do
    OUR_FILES[${#OUR_FILES[@]}]=$source_file
done < "$STATIC_TMP/sources.sorted"
if [ "${#OUR_FILES[@]}" -eq 0 ]; then
    F "source discovery returned no first-party translation units"
    exit 1
fi

# Conversion warnings are intentionally a second, narrower policy.  The LZ,
# LZH, Keccak, and ML-KEM implementations use signed loop indices per their
# reviewed algorithms; the strict-Werror and cppcheck passes still cover them.
CONVERSION_FILES=(
    src/zupt_main.c src/zupt_format.c src/zupt_dedup.c src/zupt_disk.c
    src/zupt_crypto.c src/zupt_crypto_sdk.c src/zupt_crypto_pqbox.c
    src/zupt_aes256.c src/zupt_sha256.c src/zupt_xxh.c src/zupt_parallel.c
    src/zupt_cpuid.c src/zupt_filetype.c src/zupt_mlock.c src/zupt_predict.c
    src/zupt_x25519.c
)
# zupt_sha256_shani.c needs -msha -mssse3 -msse4.1 to compile its
# intrinsics; checked separately below so the main loop stays flag-clean.
SHANI_FILE=src/zupt_sha256_shani.c
if [ ! -f "$SHANI_FILE" ]; then
    F "required SHA-NI source is missing: $SHANI_FILE"
    exit 1
fi
EXIST=("${OUR_FILES[@]}")

echo "Static analysis"

# ─── Strict GCC + -Werror ───
STRICT_CFLAGS=(
    -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes
    -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Wlogical-op
    -Wjump-misses-init -Wdouble-promotion -Woverlength-strings -Werror
    -O2 -std=c11 -Iinclude -Isrc
)

STRICT_FAILS=0
for f in "${EXIST[@]}"; do
    if ! "$STATIC_CC" "${STRICT_CFLAGS[@]}" -c "$f" -o /dev/null 2>"$STATIC_TMP/strict.log"; then
        STRICT_FAILS=$((STRICT_FAILS+1))
        F "strict GCC -Werror failed on $f"
        head -3 "$STATIC_TMP/strict.log" | sed 's/^/    /'
    fi
done
[ "$STRICT_FAILS" = 0 ] && P "strict GCC -Werror clean on ${#EXIST[@]} files"

# ─── -Wconversion + -Wsign-conversion ───
CONV_CFLAGS=(
    -Wall -Wextra -Wconversion -Wsign-conversion
    -O2 -std=c11 -Iinclude -Isrc
)

CONV_FAILS=0
for f in "${CONVERSION_FILES[@]}"; do
    status=0
    "$STATIC_CC" "${CONV_CFLAGS[@]}" -c "$f" -o /dev/null \
        >"$STATIC_TMP/conversion.log" 2>&1 || status=$?
    count_findings -c "warning:" "$STATIC_TMP/conversion.log"
    if [ "$status" -ne 0 ]; then
        CONV_FAILS=$((CONV_FAILS+1))
        F "$f: conversion compiler exited with status $status"
        head -3 "$STATIC_TMP/conversion.log" | sed 's/^/    /'
    elif [ "$n" != 0 ]; then
        CONV_FAILS=$((CONV_FAILS+1))
        F "$f: $n -Wconversion warnings"
        grep "warning:" "$STATIC_TMP/conversion.log" | head -3 | sed 's/^/    /'
    fi
done
[ "$CONV_FAILS" = 0 ] && P "-Wconversion -Wsign-conversion clean on ${#CONVERSION_FILES[@]} security/I/O files"

# ── SHA-NI file (needs -msha -mssse3 -msse4.1 on x86_64) ──
ARCH_SA=$(uname -m)
if [ "$ARCH_SA" = "x86_64" ] || [ "$ARCH_SA" = "i686" ]; then
    SA_SHANI=(-msha -mssse3 -msse4.1)
else
    SA_SHANI=()
fi
if "$STATIC_CC" "${STRICT_CFLAGS[@]}" "${SA_SHANI[@]}" -c "$SHANI_FILE" -o /dev/null 2>"$STATIC_TMP/shani.log"; then
    P "SHA-NI file strict GCC -Werror clean"
else
    F "SHA-NI file fails strict -Werror"
    head -5 "$STATIC_TMP/shani.log" | sed 's/^/    /'
fi
status=0
"$STATIC_CC" "${CONV_CFLAGS[@]}" "${SA_SHANI[@]}" -c "$SHANI_FILE" -o /dev/null \
    >"$STATIC_TMP/shani-conversion.log" 2>&1 || status=$?
count_findings -c 'warning:' "$STATIC_TMP/shani-conversion.log"
if [ "$status" -ne 0 ]; then
    F "SHA-NI conversion compiler exited with status $status"
    head -3 "$STATIC_TMP/shani-conversion.log" | sed 's/^/    /'
elif [ "$n" = 0 ]; then
    P "SHA-NI file -Wconversion -Wsign-conversion clean"
else
    F "SHA-NI file has -Wconversion warnings"
fi

# ─── cppcheck warning + performance ───
if command -v cppcheck >/dev/null 2>&1; then
    SUPP=$STATIC_TMP/cppcheck-suppressions.txt
    cat > "$SUPP" <<EOF
*:src/vv_ans.c
*:src/vv_decoder.c
*:src/vv_encoder.c
*:src/vv_huffman.c
*:src/vv_simd.c
*:src/vv_xxh64.c
*:src/fips202.c
missingIncludeSystem
EOF
    status=0
    timeout 60 cppcheck --quiet --enable=warning,performance \
        --inline-suppr --error-exitcode=0 \
        -Iinclude -Isrc --max-configs=2 \
        --suppressions-list="$SUPP" \
        "${EXIST[@]}" >"$STATIC_TMP/cppcheck-warning.log" 2>&1 || status=$?
    count_findings -cE "warning:|error:|performance:" "$STATIC_TMP/cppcheck-warning.log"
    if [ "$status" -ne 0 ]; then
        F "cppcheck warning+performance exited with status $status"
        head -5 "$STATIC_TMP/cppcheck-warning.log" | sed 's/^/    /'
    elif [ "$n" = 0 ]; then
        P "cppcheck warning+performance: 0 findings"
    else
        F "cppcheck warning+performance: $n findings"
        grep -E "warning:|error:|performance:" "$STATIC_TMP/cppcheck-warning.log" |
            head -5 | sed 's/^/    /'
    fi

    # Specifically: no `knownConditionTrueFalse` style findings on our code
    status=0
    timeout 60 cppcheck --quiet --enable=style \
        --inline-suppr -Iinclude -Isrc --max-configs=2 \
        --suppressions-list="$SUPP" \
        "${EXIST[@]}" >"$STATIC_TMP/cppcheck-style.log" 2>&1 || status=$?
    count_findings -c "knownConditionTrueFalse" "$STATIC_TMP/cppcheck-style.log"
    if [ "$status" -ne 0 ]; then
        F "cppcheck style exited with status $status"
        head -5 "$STATIC_TMP/cppcheck-style.log" | sed 's/^/    /'
    elif [ "$n" = 0 ]; then
        P "cppcheck: no knownConditionTrueFalse findings (dead conditions)"
    else
        F "cppcheck: $n knownConditionTrueFalse findings"
        grep "knownConditionTrueFalse" "$STATIC_TMP/cppcheck-style.log" |
            head -3 | sed 's/^/    /'
    fi

    # Critical: no error-level findings
    status=0
    timeout 60 cppcheck --quiet \
        --inline-suppr --error-exitcode=0 \
        -Iinclude -Isrc --max-configs=2 \
        --suppressions-list="$SUPP" \
        "${EXIST[@]}" >"$STATIC_TMP/cppcheck-error.log" 2>&1 || status=$?
    count_findings -cE "error:" "$STATIC_TMP/cppcheck-error.log"
    if [ "$status" -ne 0 ]; then
        F "cppcheck error-level scan exited with status $status"
        head -5 "$STATIC_TMP/cppcheck-error.log" | sed 's/^/    /'
    elif [ "$n" = 0 ]; then
        P "cppcheck error level: 0 findings"
    else
        F "cppcheck error level: $n findings"
    fi
else
    echo "  - skipped: cppcheck not installed"
fi

# ─── Specific dead-code regression checks ───
# The varint decoders used to have `if(s>=64 && (x&0x80))return -1;`
# where the AND was dead. Ensure that pattern doesn't come back.
if checked_grep -nE "s>=64 *&& *\([cx]&0x80\)" src/zupt_format.c >/dev/null; then
    F "varint decoder has the dead 's>=64 && (x|c)&0x80' pattern back"
    grep -nE "s>=64 *&& *\([cx]&0x80\)" src/zupt_format.c | sed 's/^/    /'
else
    P "varint decoders don't have the v3.0.2 dead-AND pattern"
fi

# ECHO bit-clear: should have explicit (tcflag_t) cast
if checked_grep -qE 'c_lflag &= \(tcflag_t\)~ECHO' src/zupt_main.c; then
    P "ECHO bit-clear uses explicit (tcflag_t) cast"
else
    F "ECHO bit-clear missing the explicit (tcflag_t) cast"
fi

# A restore to a device is irreversible.  Classify the already-open descriptor
# rather than checking target_path and resolving that mutable name again.
if checked_grep -Fq 'lstat(target_path' src/zupt_disk.c; then
    F "disk restore has a path-check/open TOCTOU pattern"
elif checked_grep -Fq 'tgt_fd = open(target_path' src/zupt_disk.c &&
     checked_grep -Fq 'fstat(tgt_fd, &opened_st)' src/zupt_disk.c; then
    P "disk restore classifies the opened target descriptor"
else
    F "disk restore descriptor-first target guard is missing"
fi

# CodeQL #5 reported chmod(dst, mode) after reopening/resolving the SDK save
# path.  Key copies must use the core's handle/descriptor-relative atomic
# publisher and apply POSIX permissions to its already-open temporary stream.
if checked_grep -Fq 'chmod(dst, mode)' sdk/src/zuptsdk.c; then
    F "SDK key save has a path-based chmod TOCTOU pattern"
elif checked_grep -Fq 'zupt_atomic_output_open(dst, &fo)' sdk/src/zuptsdk.c &&
     checked_grep -Fq 'fchmod(fileno(fo), mode)' sdk/src/zuptsdk.c &&
     checked_grep -Fq 'zupt_atomic_output_finish(output, rc == ZUPTSDK_OK)' \
         sdk/src/zuptsdk.c; then
    P "SDK key save uses descriptor-relative atomic publication"
else
    F "SDK key save atomic publication guard is missing"
fi

# The SDK regression must not recreate the same check/use pattern while
# inspecting its sentinels and key modes. Open once, then classify/read via
# that descriptor; this also keeps CodeQL evidence free of test-only races.
if checked_grep -Eq '(^|[^[:alnum:]_])(stat|lstat)[[:space:]]*\(' \
        sdk/tests/test_sdk_roundtrip.c; then
    F "SDK regression uses path-level stat/lstat before later path operations"
elif checked_grep -Fq 'fstat(fd, &info)' sdk/tests/test_sdk_roundtrip.c &&
     checked_grep -Fq 'fstat(fd, info)' sdk/tests/test_sdk_roundtrip.c; then
    P "SDK regression inspects already-open file descriptors"
else
    F "SDK regression descriptor-based inspection guard is missing"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  Static analysis: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
