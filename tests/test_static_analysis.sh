#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Static-analysis regression for v3.0.3.
#
# Asserts that our (non-vendored) C source compiles cleanly under:
#   - GCC strict warnings + -Werror
#   - GCC -Wconversion + -Wsign-conversion (silenced/false-positive-prone
#     warnings; we enable for OUR code only, not vendored vv_*.c)
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
P() { echo "  ✓ $1"; PASS=$((PASS+1)); }
F() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

# Our (non-vendored) C source files. Vendored: vv_*.c, fips202.c,
# zupt_mlkem.c — these have their own upstream style and we don't
# enforce our warning set on them.
OUR_FILES=(
    src/zupt_main.c
    src/zupt_format.c
    src/zupt_dedup.c
    src/zupt_disk.c
    src/zupt_crypto.c
    src/zupt_aes256.c
    src/zupt_sha256.c
    src/zupt_xxh.c
    src/zupt_parallel.c
)
# zupt_sha256_shani.c needs -msha -mssse3 -msse4.1 to compile its
# intrinsics; checked separately below so the main loop stays flag-clean.
SHANI_FILE=src/zupt_sha256_shani.c
# Filter to files that actually exist (architecture-conditional ones)
EXIST=()
for f in "${OUR_FILES[@]}"; do
    [ -f "$f" ] && EXIST+=("$f")
done

echo "Static analysis"

# ─── Strict GCC + -Werror ───
STRICT_CFLAGS="-Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes \
-Wmissing-prototypes -Wnull-dereference -Wformat=2 -Wlogical-op -Wjump-misses-init \
-Wdouble-promotion -Woverlength-strings -Werror -O2 -std=c11 -Iinclude -Isrc"

STRICT_FAILS=0
for f in "${EXIST[@]}"; do
    if ! gcc $STRICT_CFLAGS -c "$f" -o /dev/null 2>/tmp/sa-strict.log; then
        STRICT_FAILS=$((STRICT_FAILS+1))
        F "strict GCC -Werror failed on $f"
        head -3 /tmp/sa-strict.log | sed 's/^/    /'
    fi
done
[ "$STRICT_FAILS" = 0 ] && P "strict GCC -Werror clean on ${#EXIST[@]} files"

# ─── -Wconversion + -Wsign-conversion ───
CONV_CFLAGS="-Wall -Wextra -Wconversion -Wsign-conversion -O2 -std=c11 -Iinclude -Isrc"

CONV_FAILS=0
for f in "${EXIST[@]}"; do
    n=$(gcc $CONV_CFLAGS -c "$f" -o /dev/null 2>&1 | grep -c "warning:")
    if [ "$n" -gt 0 ]; then
        CONV_FAILS=$((CONV_FAILS+1))
        F "$f: $n -Wconversion warnings"
        gcc $CONV_CFLAGS -c "$f" -o /dev/null 2>&1 | grep "warning:" | head -3 | sed 's/^/    /'
    fi
done
[ "$CONV_FAILS" = 0 ] && P "-Wconversion -Wsign-conversion clean on ${#EXIST[@]} files"

# ── SHA-NI file (needs -msha -mssse3 -msse4.1 on x86_64) ──
if [ -f "$SHANI_FILE" ]; then
    ARCH_SA=$(uname -m)
    if [ "$ARCH_SA" = "x86_64" ] || [ "$ARCH_SA" = "i686" ]; then
        SA_SHANI="-msha -mssse3 -msse4.1"
    else
        SA_SHANI=""
    fi
    if gcc $STRICT_CFLAGS $SA_SHANI -c "$SHANI_FILE" -o /dev/null 2>/tmp/sa-shani.log; then
        P "SHA-NI file strict GCC -Werror clean"
    else
        F "SHA-NI file fails strict -Werror"
        head -5 /tmp/sa-shani.log | sed 's/^/    /'
    fi
    if [ "$(gcc $CONV_CFLAGS $SA_SHANI -c "$SHANI_FILE" -o /dev/null 2>&1 | grep -c 'warning:')" = 0 ]; then
        P "SHA-NI file -Wconversion -Wsign-conversion clean"
    else
        F "SHA-NI file has -Wconversion warnings"
    fi
fi

# ─── cppcheck warning + performance ───
if command -v cppcheck >/dev/null 2>&1; then
    SUPP=/tmp/cppcheck-supp-sa.txt
    cat > "$SUPP" <<EOF
*:src/vv_ans.c
*:src/vv_decoder.c
*:src/vv_encoder.c
*:src/vv_huffman.c
*:src/vv_simd.c
*:src/vv_xxh64.c
*:src/fips202.c
*:src/zupt_mlkem.c
missingIncludeSystem
EOF
    n=$(timeout 60 cppcheck --quiet --enable=warning,performance \
        --inline-suppr --error-exitcode=0 \
        -Iinclude -Isrc --max-configs=2 \
        --suppressions-list="$SUPP" \
        "${EXIST[@]}" 2>&1 | grep -cE "warning:|error:|performance:")
    if [ "$n" = 0 ]; then
        P "cppcheck warning+performance: 0 findings"
    else
        F "cppcheck warning+performance: $n findings"
        timeout 60 cppcheck --quiet --enable=warning,performance \
            --inline-suppr -Iinclude -Isrc --max-configs=2 \
            --suppressions-list="$SUPP" \
            "${EXIST[@]}" 2>&1 | grep -E "warning:|error:|performance:" | head -5 | sed 's/^/    /'
    fi

    # Specifically: no `knownConditionTrueFalse` style findings on our code
    n=$(timeout 60 cppcheck --quiet --enable=style \
        --inline-suppr -Iinclude -Isrc --max-configs=2 \
        --suppressions-list="$SUPP" \
        "${EXIST[@]}" 2>&1 | grep -c "knownConditionTrueFalse")
    if [ "$n" = 0 ]; then
        P "cppcheck: no knownConditionTrueFalse findings (dead conditions)"
    else
        F "cppcheck: $n knownConditionTrueFalse findings"
        timeout 60 cppcheck --quiet --enable=style \
            --inline-suppr -Iinclude -Isrc --max-configs=2 \
            --suppressions-list="$SUPP" \
            "${EXIST[@]}" 2>&1 | grep "knownConditionTrueFalse" | head -3 | sed 's/^/    /'
    fi

    # Critical: no error-level findings
    n=$(timeout 60 cppcheck --quiet \
        --inline-suppr --error-exitcode=0 \
        -Iinclude -Isrc --max-configs=2 \
        --suppressions-list="$SUPP" \
        "${EXIST[@]}" 2>&1 | grep -cE "error:")
    if [ "$n" = 0 ]; then
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
if grep -nE "s>=64 *&& *\([cx]&0x80\)" src/zupt_format.c >/dev/null 2>&1; then
    F "varint decoder has the dead 's>=64 && (x|c)&0x80' pattern back"
    grep -nE "s>=64 *&& *\([cx]&0x80\)" src/zupt_format.c | sed 's/^/    /'
else
    P "varint decoders don't have the v3.0.2 dead-AND pattern"
fi

# ECHO bit-clear: should have explicit (tcflag_t) cast
if grep -qE 'c_lflag &= \(tcflag_t\)~ECHO' src/zupt_main.c; then
    P "ECHO bit-clear uses explicit (tcflag_t) cast"
else
    F "ECHO bit-clear missing the explicit (tcflag_t) cast"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  Static analysis: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
