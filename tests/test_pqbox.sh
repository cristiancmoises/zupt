#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
#
# ZUPT_ENC_PQ_BOX_V1 (--pq-box, vendored libpqvaptvupt) — functional and
# adversarial coverage: keygen file format, byte-exact roundtrips on both
# frame formats, wrong-key and key-type-confusion rejection, envelope and
# data tampering, and cross-mode isolation.

set -u
P=0; F=0
ok()  { echo "  ✓ $1"; P=$((P+1)); }
bad() { echo "  ✗ $1"; F=$((F+1)); }
T=$(mktemp -d)
FX=/tmp/bench/fixtures
BIN=./vaptvupt

echo "pq-box mode (ZUPT_ENC_PQ_BOX_V1)"

# 1. keygen + file format
$BIN keygen --box -o $T/k.key >/dev/null 2>&1
[ "$(stat -c%s $T/k.key 2>/dev/null)" = "2441" ] && ok "secret keyfile size (9+2432)" || bad "secret keyfile size"
[ "$(stat -c%s $T/k.key.pub 2>/dev/null)" = "1225" ] && ok "public keyfile size (9+1216)" || bad "public keyfile size"
head -c8 $T/k.key | grep -q "PQVVBOX1" && ok "keyfile magic" || bad "keyfile magic"

# 2. roundtrips: L1 (v1 frame) and L9 (format_v2 + auto-filter), text + binary
for case in "1 text" "9 text" "9 binary"; do
  set -- $case; L=$1; fx=$2
  $BIN c -l $L --pq-box $T/k.key.pub $T/a$L$fx.zupt $FX/$fx.dat >/dev/null 2>&1
  rm -rf $T/o$L$fx; mkdir -p $T/o$L$fx
  $BIN x --pq-box $T/k.key -o $T/o$L$fx $T/a$L$fx.zupt >/dev/null 2>&1
  Fp=$(find $T/o$L$fx -type f | head -1)
  [ -n "$Fp" ] && diff -q "$Fp" $FX/$fx.dat >/dev/null 2>&1 \
    && ok "roundtrip L$L $fx byte-exact" || bad "roundtrip L$L $fx"
done

# 3. wrong key rejected
$BIN keygen --box -o $T/w.key >/dev/null 2>&1
rm -rf $T/ow; mkdir -p $T/ow
$BIN x --pq-box $T/w.key -o $T/ow $T/a9text.zupt >/dev/null 2>&1 \
  && bad "wrong key accepted" || ok "wrong key rejected"

# 4. key-type confusion rejected (pub-as-priv, priv-as-pub, legacy key)
rm -rf $T/oc; mkdir -p $T/oc
$BIN x --pq-box $T/k.key.pub -o $T/oc $T/a9text.zupt >/dev/null 2>&1 \
  && bad "PUBLIC key accepted as secret" || ok "public-as-secret rejected"
$BIN c -l 1 --pq-box $T/k.key $T/cc.zupt $FX/text.dat >/dev/null 2>&1 \
  && bad "SECRET key accepted as public" || ok "secret-as-public rejected"
$BIN keygen -o $T/legacy.key >/dev/null 2>&1
rm -rf $T/ol; mkdir -p $T/ol
$BIN x --pq-box $T/legacy.key -o $T/ol $T/a9text.zupt >/dev/null 2>&1 \
  && bad "legacy key accepted on box archive" || ok "legacy-key-on-box rejected"

# 5. tamper: envelope byte (offset inside the sealed blob) and data region
for spot in 64 -1024; do
  cp $T/a9text.zupt $T/t.zupt
  python3 - "$T/t.zupt" "$spot" << 'PY'
import sys
p, off = sys.argv[1], int(sys.argv[2])
d = bytearray(open(p,'rb').read())
i = off if off >= 0 else len(d)+off
d[i] ^= 0x01
open(p,'wb').write(d)
PY
  rm -rf $T/ot; mkdir -p $T/ot
  $BIN x --pq-box $T/k.key -o $T/ot $T/t.zupt >/dev/null 2>&1 \
    && bad "tamper@$spot accepted" || ok "tamper@$spot rejected"
done

# 6. cross-mode isolation: box archive demands box key, not password
rm -rf $T/op; mkdir -p $T/op
$BIN x -p somepass -o $T/op $T/a9text.zupt >/dev/null 2>&1 \
  && bad "password accepted on box archive" || ok "password-on-box rejected"

echo ""
echo "  ───────────────────────────────────────"
echo "  pq-box: $P passed, $F failed"
echo "  ───────────────────────────────────────"
rm -rf $T
exit $([ $F -eq 0 ] && echo 0 || echo 1)
