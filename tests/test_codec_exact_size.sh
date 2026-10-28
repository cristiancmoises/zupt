#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
#
# Exact-content_size decode OOB regression (codec 2.60.4 fix) under ASan,
# plus a tool-level BCJ roundtrip on a real binary fixture at the levels
# where the auto-filter engages. Codec sources are compiled directly with
# -fsanitize=address (never link sanitized objects against the project's
# non-sanitized .o files — ASan static-archive poisoning).

set -u
ARCH=$(uname -m)
SIMD=""
if [[ $ARCH == x86_64 ]] && grep -qiw avx2 /proc/cpuinfo 2>/dev/null; then
    SIMD="-mavx2"
else
    echo "  SKIP: AVX2-specific subpath unavailable; scalar exact-size test remains enabled"
fi

TMP=$(mktemp -d) || exit 1
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
rc=0

echo "Codec exact-size + BCJ roundtrip"

# Direct invocation uses the selected driver too; make supplies its policy.
# Compiler and flag lists intentionally follow make-compatible word splitting.
if [[ ! ${VV_CAST_ALIGN_FLAGS+x} ]]; then
    VV_CAST_ALIGN_FLAGS=""
    case $(${CC:-cc} --version 2>/dev/null | sed -n '1p') in
        *clang*) VV_CAST_ALIGN_FLAGS=-Wno-cast-align ;;
    esac
fi
objects=()
compile_ok=1
for source in tests/test_codec_exact_size.c \
              src/vaptvupt_api.c src/vv_ans.c src/vv_bcj.c src/vv_decoder.c \
              src/vv_encoder.c src/vv_huffman.c src/vv_simd.c src/vv_xxh64.c; do
    extra_cflags=""
    case $source in
        src/vv_ans.c|src/vv_simd.c) extra_cflags=$VV_CAST_ALIGN_FLAGS ;;
    esac
    object="$TMP/${source##*/}.o"
    # shellcheck disable=SC2086
    if ${CC:-cc} ${CPPFLAGS:-} ${CFLAGS--O1 -g} \
           -D_DEFAULT_SOURCE -Iinclude -Isrc -Wall -Wextra -Werror -std=c11 \
           -fsanitize=address $SIMD $extra_cflags -c "$source" -o "$object" \
           2>>"$TMP/cc.log"; then
        objects+=("$object")
    else
        compile_ok=0
        break
    fi
done
# shellcheck disable=SC2086
if [[ $compile_ok == 1 ]] && \
   ${CC:-cc} ${CFLAGS--O1 -g} -fsanitize=address ${LDFLAGS:-} \
       "${objects[@]}" -o "$TMP/t" ${LDLIBS:-} 2>>"$TMP/cc.log"; then
    "$TMP/t"; rc=$?
else
    echo "  ✗ exact-size test failed to compile or link"
    sed 's/^/    /' "$TMP/cc.log"
    rc=1
fi

# Tool-level BCJ roundtrip: real binary fixture at L5 (BALANCED+auto-filter)
# and L9 (EXTREME+auto-filter); byte-exact extraction required. Guards the
# F-16 defect class (old in-tree BCJ wrote undecodable streams).
FX=${ZUPT_BIN:-./zupt}
bcj_failure() {
    printf '  ✗ BCJ L%s %s failed (status %s)\n' "$L" "$1" "$2"
    cat -- "$3"
    rc=1
}
if [ -f "$FX" ] && [ -x ./zupt ]; then
    for L in 5 9; do
        log="$TMP/bcj-$L.log"
        if mkdir -- "$TMP/o$L" >"$log" 2>&1; then :
        else bcj_failure setup "$?" "$log"; continue
        fi
        if ./zupt c -l "$L" "$TMP/a$L.zupt" "$FX" >"$log" 2>&1; then :
        else bcj_failure compression "$?" "$log"; continue
        fi
        if ./zupt x -o "$TMP/o$L" "$TMP/a$L.zupt" >"$log" 2>&1; then :
        else bcj_failure extraction "$?" "$log"; continue
        fi
        # Check the complete producer before reading its output. A failed find
        # can still emit the correct member; head also hides additional files.
        if find "$TMP/o$L" -type f -print0 >"$TMP/members$L" 2>"$log"; then :
        else bcj_failure enumeration "$?" "$log"; continue
        fi
        files=()
        while IFS= read -r -d '' F; do files+=("$F"); done <"$TMP/members$L"
        if [[ ${#files[@]} != 1 ]]; then
            printf '  ✗ BCJ L%s expected one extracted file, got %s\n' "$L" "${#files[@]}"
            rc=1
            continue
        fi
        if diff -q -- "${files[0]}" "$FX" >"$log" 2>&1; then
            echo "  ✓ BCJ roundtrip L$L (binary fixture) byte-exact"
        else
            bcj_failure comparison "$?" "$log"
        fi
    done
else
    echo "  - BCJ tool roundtrip skipped (source-built executable missing)"
fi

exit $rc
