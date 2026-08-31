#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Functional and adversarial coverage for the optional system libvuptsdk.

set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
zupt=${ZUPT_BIN:-$repo_root/zupt}

if [[ ! -x $zupt ]]; then
    printf '  FAIL: %s not found; build ZUPT first\n' "$zupt" >&2
    exit 1
fi

version=$("$zupt" --version 2>&1)
if ! grep -Fq 'libvuptsdk=enabled' <<<"$version"; then
    echo '  SKIP: system libvuptsdk integration is disabled (build with WITH_SDK=1)'
    exit 0
fi

tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
cd "$tmpdir"

passed=0
failed=0
pass() { printf '  OK:   %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf '  FAIL: %s\n' "$1"; failed=$((failed + 1)); }

if "$zupt" keygen --sdk -o key.priv >/dev/null 2>&1 &&
   [[ -f key.priv && -f key.priv.pub ]]; then
    pass 'SDK keygen produces private and public key files'
else
    fail 'SDK keygen using system libvuptsdk'
    exit 1
fi

printf 'Hello SDK PQ encryption\n' >input.txt
dd if=/dev/urandom of=large.bin bs=65536 count=4 2>/dev/null

if "$zupt" c --pq-sdk key.priv.pub small.zupt input.txt >/dev/null 2>&1; then
    pass 'SDK encrypts a small file'
else
    fail 'SDK encrypts a small file'
fi
mkdir extract1
if (cd extract1 && "$zupt" x --pq-sdk ../key.priv ../small.zupt >/dev/null 2>&1); then
    pass 'SDK decrypts a small file'
else
    fail 'SDK decrypts a small file'
fi
if cmp -s input.txt extract1/input.txt; then
    pass 'SDK small roundtrip is byte-exact'
else
    fail 'SDK small roundtrip is byte-exact'
fi

if "$zupt" c --pq-sdk key.priv.pub large.zupt large.bin >/dev/null 2>&1; then
    pass 'SDK encrypts a 256 KiB file'
else
    fail 'SDK encrypts a 256 KiB file'
fi
mkdir extract2
if (cd extract2 && "$zupt" x --pq-sdk ../key.priv ../large.zupt >/dev/null 2>&1); then
    pass 'SDK decrypts a 256 KiB file'
else
    fail 'SDK decrypts a 256 KiB file'
fi
if cmp -s large.bin extract2/large.bin; then
    pass 'SDK large roundtrip is byte-exact'
else
    fail 'SDK large roundtrip is byte-exact'
fi

"$zupt" keygen --sdk -o other.priv >/dev/null 2>&1
mkdir wrong-key
if (cd wrong-key && "$zupt" x --pq-sdk ../other.priv ../small.zupt >/dev/null 2>&1); then
    fail 'SDK rejects the wrong private key'
else
    pass 'SDK rejects the wrong private key'
fi

cp small.zupt tampered.zupt
python3 - <<'PY'
from pathlib import Path

path = Path("tampered.zupt")
data = bytearray(path.read_bytes())
if len(data) <= 200:
    raise SystemExit("archive too small for deterministic body tamper")
data[200] ^= 1
path.write_bytes(data)
PY
mkdir tampered
if (cd tampered && "$zupt" x --pq-sdk ../key.priv ../tampered.zupt >/dev/null 2>&1); then
    fail 'SDK rejects tampered ciphertext'
else
    pass 'SDK rejects tampered ciphertext'
fi

"$zupt" keygen -o native.key >/dev/null 2>&1
if "$zupt" c --pq native.key native.zupt input.txt >/dev/null 2>&1; then
    pass 'native --pq encryption remains available'
else
    fail 'native --pq encryption remains available'
fi
mkdir native-out
if (cd native-out && "$zupt" x --pq ../native.key ../native.zupt >/dev/null 2>&1) &&
   cmp -s input.txt native-out/input.txt; then
    pass 'native --pq roundtrip remains byte-exact'
else
    fail 'native --pq roundtrip remains byte-exact'
fi

printf '\n  Results: %d passed, %d failed (%d tests)\n' \
    "$passed" "$failed" "$((passed + failed))"
((failed == 0))
