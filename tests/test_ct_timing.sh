#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# dudect-style timing regression measurement for zupt_ct_memeq (v3.5.0).
# Builds the actual production primitive at -O2 by default. Its volatile byte
# reads and generated instructions remain compiler/platform-dependent.
#
# Verdict is environment-relative: zupt_ct_memeq's data-dependent timing
# signal must be a small fraction (<=20%) of the deliberate early-exit control
# measured in the matched balanced records, with counterbalanced comparator
# order and a label-only negative control. Libc memcmp is diagnostic only.
# INCONCLUSIVE exits77, distinct from PASS0/FAIL1;
# timer/statistics errors exit2. This does not certify constant-time behavior.

set -u
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "i686" ]; then
    SHANI="-msha -mssse3 -msse4.1"
else
    SHANI=""
fi

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
# This test uses only native CT primitives; it deliberately has no optional
# SDK linkage so the baseline source build is the exact path under test.
# Flag lists follow the established intentional whitespace-splitting convention.
# SHA-NI alone inherits the existing Makefile's scoped Clang alignment policy.
# shellcheck disable=SC2086
if "${CC:-cc}" ${CPPFLAGS:-} -D_DEFAULT_SOURCE -Iinclude -Isrc \
       ${CFLAGS:--O2} -Wall -Wextra -Werror $SHANI -std=c11 \
       ${SHANI_CFLAGS:-} -c src/zupt_sha256_shani.c -o "$TMP/shani.o" 2>"$TMP/cc.log" &&
   "${CC:-cc}" ${CPPFLAGS:-} -D_DEFAULT_SOURCE -Iinclude -Isrc \
       ${CFLAGS:--O2} -Wall -Wextra -Werror $SHANI -std=c11 ${LDFLAGS:-} \
       tests/test_ct_timing.c \
       src/zupt_crypto.c src/zupt_sha256.c src/zupt_aes256.c \
       src/zupt_xxh.c src/zupt_keccak.c src/zupt_x25519.c src/zupt_mlkem.c \
       src/zupt_cpuid.c src/zupt_mlock.c "$TMP/shani.o" \
       -lm ${LDLIBS:-} \
       -o "$TMP/t" 2>>"$TMP/cc.log"; then
    "$TMP/t"; rc=$?
else
    echo "  ✗ constant-time test failed to compile"
    sed 's/^/    /' "$TMP/cc.log"
    rc=1
fi

# Source-routing guard: the security-critical compares must use the single
# audited zupt_ct_memeq primitive, not a reintroduced inline byte-OR loop.
# This confirms that the measured primitive is also used by the ML-KEM
# 1088-byte decapsulation comparison; it is not a formal timing proof.
echo ""
echo "  -- source routing (audited primitive) --"
ROUTE_OK=0
grep -q "zupt_ct_memeq(ct, ct_prime, 1088)" src/zupt_mlkem.c
route_rc=$?
case "$route_rc" in
    0) echo "  ✓ ML-KEM decaps compare routes through zupt_ct_memeq" ;;
    1) echo "  ✗ ML-KEM decaps compare does NOT use zupt_ct_memeq"; ROUTE_OK=1 ;;
    *) echo "  ERROR: ML-KEM routing scan failed (status $route_rc)"; ROUTE_OK=2 ;;
esac
# The decaps path must not contain a raw 1088-byte inline OR-compare anymore.
grep -qE "for *\(int i = 0; i < 1088;" src/zupt_mlkem.c
route_rc=$?
case "$route_rc" in
    0) echo "  ✗ raw 1088-byte inline compare loop present in zupt_mlkem.c"
       [ "$ROUTE_OK" = 2 ] || ROUTE_OK=1 ;;
    1) echo "  ✓ no raw 1088-byte inline compare loop in zupt_mlkem.c" ;;
    *) echo "  ERROR: inline compare-loop scan failed (status $route_rc)"; ROUTE_OK=2 ;;
esac
if [ "$ROUTE_OK" != 0 ]; then rc=$ROUTE_OK; fi
exit $rc
