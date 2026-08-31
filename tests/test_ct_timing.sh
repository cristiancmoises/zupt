#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# dudect-style timing regression measurement for zupt_ct_memeq (v3.5.0).
# Builds at -O2 (the shipped optimisation level — so this tests the code
# as users run it, including that the volatile accumulator survives the
# optimiser) and runs the Welch t-test harness.
#
# Verdict is environment-relative: zupt_ct_memeq's data-dependent timing
# signal must be a small fraction (<=20%) of leaky memcmp measured in the
# same environment. On a dedicated box the ratio is ~0; on this shared
# vCPU it lands near 1%. If the host is too coarse for even memcmp to
# show a leak, the test reports INCONCLUSIVE (exit 0) rather than
# passing vacuously.

set -u
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "i686" ]; then
    SHANI="-msha -mssse3 -msse4.1"
else
    SHANI=""
fi

TMP=$(mktemp -d)
# This test uses only native CT primitives; it deliberately has no optional
# SDK linkage so the baseline source build is the exact path under test.
if "${CC:-cc}" -Iinclude -Isrc -Wall -Wextra -Werror $SHANI -O2 -std=c11 \
       tests/test_ct_timing.c \
       src/zupt_crypto.c src/zupt_sha256.c src/zupt_sha256_shani.c src/zupt_aes256.c \
       src/zupt_xxh.c src/zupt_keccak.c src/zupt_x25519.c src/zupt_mlkem.c \
       src/zupt_cpuid.c src/zupt_mlock.c \
       -lm \
       -o "$TMP/t" 2>"$TMP/cc.log"; then
    "$TMP/t"; rc=$?
else
    echo "  ✗ constant-time test failed to compile"
    head -15 "$TMP/cc.log" | sed 's/^/    /'
    rc=1
fi
rm -rf "$TMP"

# Source-routing guard: the security-critical compares must use the single
# audited zupt_ct_memeq primitive, not a reintroduced inline byte-OR loop.
# This confirms that the measured primitive is also used by the ML-KEM
# 1088-byte decapsulation comparison; it is not a formal timing proof.
echo ""
echo "  -- source routing (audited primitive) --"
ROUTE_OK=0
if grep -q "zupt_ct_memeq(ct, ct_prime, 1088)" src/zupt_mlkem.c; then
    echo "  ✓ ML-KEM decaps compare routes through zupt_ct_memeq"
else
    echo "  ✗ ML-KEM decaps compare does NOT use zupt_ct_memeq (inline loop regressed?)"
    ROUTE_OK=1
fi
# The decaps path must not contain a raw 1088-byte inline OR-compare anymore.
if grep -qE "for *\(int i = 0; i < 1088;" src/zupt_mlkem.c; then
    echo "  ✗ raw 1088-byte inline compare loop present in zupt_mlkem.c"
    ROUTE_OK=1
else
    echo "  ✓ no raw 1088-byte inline compare loop in zupt_mlkem.c"
fi
[ "$rc" = 0 ] && rc=$ROUTE_OK
exit $rc
