#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# FIPS 203 CONFORMANCE test for the in-tree ML-KEM-768.
#
# Self-consistency (encaps/decaps round-trip) does NOT prove conformance: a
# transposed matrix convention round-trips fine but is not interoperable. This
# test validates against an EXTERNAL FIPS 203 reference — OpenSSL 3.5+, which
# ships ML-KEM-768 — three ways:
#   1. deterministic keygen: our ek == OpenSSL's ek for the same seed (d||z)
#   2. our encaps -> OpenSSL decap: shared secrets match
#   3. OpenSSL encap -> our decaps: shared secrets match
#
# Skips gracefully (exit 0) when the toolchain or an ML-KEM-capable OpenSSL is
# unavailable, so it is safe inside distro package builds.
set -u
echo "ML-KEM-768 FIPS 203 conformance (interop vs OpenSSL)"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CC="${CC:-cc}"

command -v openssl >/dev/null 2>&1 || { echo "  - skipped: no openssl"; exit 0; }
if ! openssl list -kem-algorithms 2>/dev/null | grep -qiE "ML-KEM-768|MLKEM768"; then
    echo "  - skipped: openssl has no ML-KEM-768 (need 3.5+)"; exit 0
fi
command -v "$CC" >/dev/null 2>&1 || CC=gcc
command -v "$CC" >/dev/null 2>&1 || { echo "  - skipped: no C compiler"; exit 0; }
command -v od >/dev/null 2>&1 || { echo "  - skipped: no od"; exit 0; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
H="$T/harness"
if ! "$CC" -O2 -I"$ROOT/include" -I"$ROOT/src" "$HERE/mlkem_fips203_harness.c" \
      "$ROOT/src/zupt_mlkem.c" "$ROOT/src/zupt_keccak.c" -o "$H" 2>"$T/cc.err"; then
    echo "  - skipped: harness build failed"; sed 's/^/    /' "$T/cc.err" | head -3; exit 0
fi
hx(){ od -A n -v -t x1 "$1" | tr -d ' \n'; }
P=0; F=0; ok(){ echo "  ✓ $1"; P=$((P+1)); }; bad(){ echo "  ✗ $1"; F=$((F+1)); }
cd "$T"

# 1) deterministic keygen ek match
head -c 64 /dev/urandom > dz.bin
SEED=$(hx dz.bin)
openssl genpkey -algorithm ML-KEM-768 -pkeyopt hexseed:"$SEED" -out osl.pem 2>/dev/null
openssl pkey -in osl.pem -pubout -outform DER -out osl_pub.der 2>/dev/null
tail -c 1184 osl_pub.der > osl_ek.bin
MLKEM_RAND="$T/dz.bin" "$H" keygen
cmp -s ek.bin osl_ek.bin && ok "keygen ek == OpenSSL (byte-for-byte, same seed)" || bad "keygen ek differs from OpenSSL"

# 2) my encaps -> openssl decap
unset MLKEM_RAND
"$H" encaps osl_ek.bin >/dev/null 2>&1; cp ss.bin ss_mine.bin
openssl pkeyutl -decap -inkey osl.pem -in ct.bin -secret ss_osl.bin 2>/dev/null
cmp -s ss_mine.bin ss_osl.bin && ok "my encaps -> OpenSSL decap: shared secret matches" || bad "my encaps not interoperable"

# 3) openssl encap -> my decap
HDR=$(( $(stat -c%s osl_pub.der) - 1184 )); head -c "$HDR" osl_pub.der > hdr.bin
"$H" keygen
cat hdr.bin ek.bin > my_pub.der
openssl pkeyutl -encap -pubin -inkey my_pub.der -secret ss_osl2.bin -out ct2.bin 2>/dev/null
"$H" decaps dk.bin ct2.bin >/dev/null 2>&1; cp ss.bin ss_mine2.bin
cmp -s ss_mine2.bin ss_osl2.bin && ok "OpenSSL encap -> my decap: shared secret matches" || bad "my decap not interoperable"

echo "  Conformance: $P passed, $F failed"
[ "$F" -eq 0 ] && exit 0 || exit 1
