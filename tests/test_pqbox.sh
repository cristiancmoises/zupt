#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Functional and adversarial coverage for the optional system libpqvaptvupt.

set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
zupt=${ZUPT_BIN:-$repo_root/zupt}

if [[ ! -x $zupt ]]; then
    printf '  FAIL: %s not found; build ZUPT first\n' "$zupt" >&2
    exit 1
fi

version=$("$zupt" --version 2>&1)
if ! grep -Fq 'libpqvaptvupt=enabled' <<<"$version"; then
    echo '  SKIP: system libpqvaptvupt integration is disabled (build with WITH_PQBOX=1)'
    exit 0
fi

tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
cd "$tmpdir"

passed=0
failed=0
pass() { printf '  ✓ %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf '  ✗ %s\n' "$1"; failed=$((failed + 1)); }

echo 'pq-box mode (ZUPT_ENC_PQ_BOX_V1)'

if "$zupt" keygen --box -o k.key >/dev/null 2>&1 &&
   [[ -f k.key && -f k.key.pub ]]; then
    pass 'pq-box keygen produces private and public key files'
else
    fail 'pq-box keygen using system libpqvaptvupt'
    exit 1
fi
if [[ $(wc -c <k.key) -eq 2441 ]]; then
    pass 'secret keyfile size is 9+2432 bytes'
else
    fail 'secret keyfile size'
fi
if [[ $(wc -c <k.key.pub) -eq 1225 ]]; then
    pass 'public keyfile size is 9+1216 bytes'
else
    fail 'public keyfile size'
fi
if [[ $(head -c 8 k.key) == PQVVBOX1 ]]; then
    pass 'keyfile magic is PQVVBOX1'
else
    fail 'keyfile magic'
fi

printf 'ZUPT pq-box text fixture with UTF-8: segurança\n' >text.dat
dd if=/dev/urandom of=binary.dat bs=65536 count=4 2>/dev/null

for level in 1 9 9; do
    if [[ $level -eq 1 ]]; then
        fixture=text.dat
        label='L1 text'
    elif [[ ! -e a9text.zupt ]]; then
        fixture=text.dat
        label='L9 text'
    else
        fixture=binary.dat
        label='L9 binary'
    fi
    archive="a${level}${fixture%.dat}.zupt"
    outdir="out-${level}-${fixture%.dat}"
    if "$zupt" c -l "$level" --pq-box k.key.pub "$archive" "$fixture" >/dev/null 2>&1; then
        mkdir "$outdir"
        if "$zupt" x --pq-box k.key -o "$outdir" "$archive" >/dev/null 2>&1 &&
           cmp -s "$fixture" "$outdir/$fixture"; then
            pass "roundtrip $label is byte-exact"
        else
            fail "roundtrip $label is byte-exact"
        fi
    else
        fail "encrypt $label"
    fi
done

"$zupt" keygen --box -o wrong.key >/dev/null 2>&1
mkdir wrong-out
if "$zupt" x --pq-box wrong.key -o wrong-out a9text.zupt >/dev/null 2>&1; then
    fail 'wrong pq-box key is rejected'
else
    pass 'wrong pq-box key is rejected'
fi

mkdir confusion-out
if "$zupt" x --pq-box k.key.pub -o confusion-out a9text.zupt >/dev/null 2>&1; then
    fail 'public key is rejected as a secret key'
else
    pass 'public key is rejected as a secret key'
fi
if "$zupt" c -l 1 --pq-box k.key secret-as-public.zupt text.dat >/dev/null 2>&1; then
    fail 'secret key is rejected as a public key'
else
    pass 'secret key is rejected as a public key'
fi
"$zupt" keygen -o native.key >/dev/null 2>&1
mkdir native-confusion-out
if "$zupt" x --pq-box native.key -o native-confusion-out a9text.zupt >/dev/null 2>&1; then
    fail 'native key is rejected for a pq-box archive'
else
    pass 'native key is rejected for a pq-box archive'
fi

for position in envelope body; do
    kind=data
    [[ $position == envelope ]] && kind=enc
    python3 "$repo_root/tests/archive_surgery.py" flip-payload \
        a9text.zupt "tampered-$position.zupt" --kind "$kind" \
        --require-encrypted
    mkdir "tampered-out-$position"
    if "$zupt" x --pq-box k.key -o "tampered-out-$position" \
        "tampered-$position.zupt" >/dev/null 2>&1; then
        fail "$position tamper is rejected"
    else
        pass "$position tamper is rejected"
    fi
done

mkdir password-out
if "$zupt" x -p somepass -o password-out a9text.zupt >/dev/null 2>&1; then
    fail 'password mode is rejected for a pq-box archive'
else
    pass 'password mode is rejected for a pq-box archive'
fi

printf '\n  pq-box: %d passed, %d failed\n' "$passed" "$failed"
((failed == 0))
