#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# F-10: KDF defaults must reflect whether system libvuptsdk is enabled.

set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
zupt=${ZUPT_BIN:-$repo_root/zupt}
if [[ ! -x $zupt ]]; then
    printf '  FAIL: %s not found; build ZUPT first\n' "$zupt" >&2
    exit 1
fi

version=$("$zupt" --version 2>&1)
sdk_enabled=0
if grep -Fq 'libvuptsdk=enabled' <<<"$version"; then
    sdk_enabled=1
fi

passed=0
failed=0
pass() { printf '  ✓ %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf '  ✗ %s\n' "$1"; failed=$((failed + 1)); }

tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
cd "$tmpdir"

enc_type_of() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

data = Path(sys.argv[1]).read_bytes()
offset = int.from_bytes(data[36:44], "little")

def read_varint(buf, pos):
    value = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7

_, pos = read_varint(data, offset + 7)
_, pos = read_varint(data, pos)
print(f"{data[pos + 8]:02x}")
PY
}

echo 'F-10 regression: password-mode KDF default'
printf 'secret payload for KDF test\n' >input.txt

default_stderr=$("$zupt" c -p secret default.zupt input.txt 2>&1)
default_type=$(enc_type_of default.zupt)
if ((sdk_enabled)); then
    if [[ $default_type == 04 ]]; then
        pass 'WITH_SDK=1 default uses Argon2id (enc_type 0x04)'
    else
        fail "WITH_SDK=1 default enc_type is 0x$default_type, expected 0x04"
    fi
    if grep -qi 'Argon2id' <<<"$default_stderr"; then
        pass 'default message names Argon2id'
    else
        fail 'default message does not name Argon2id'
    fi
else
    if [[ $default_type == 01 ]]; then
        pass 'source-only default uses PBKDF2 (enc_type 0x01)'
    else
        fail "source-only default enc_type is 0x$default_type, expected 0x01"
    fi
    if grep -qi 'PBKDF2' <<<"$default_stderr"; then
        pass 'source-only default message names PBKDF2'
    else
        fail 'source-only default message does not name PBKDF2'
    fi
    echo '  SKIP: Argon2id default/explicit coverage needs system libvuptsdk (WITH_SDK=1)'
fi

mkdir default-out
if (cd default-out && "$zupt" x -p secret ../default.zupt >/dev/null 2>&1) &&
   cmp -s input.txt default-out/input.txt; then
    pass 'default-KDF archive roundtrips byte-exact'
else
    fail 'default-KDF archive roundtrips byte-exact'
fi
mkdir default-wrong
if (cd default-wrong && "$zupt" x -p wrong ../default.zupt >/dev/null 2>&1); then
    fail 'default-KDF archive rejects a wrong password'
else
    pass 'default-KDF archive rejects a wrong password'
fi

pbkdf_stderr=$("$zupt" c -p secret --kdf pbkdf2 pbkdf.zupt input.txt 2>&1)
pbkdf_type=$(enc_type_of pbkdf.zupt)
if [[ $pbkdf_type == 01 ]]; then
    pass '--kdf pbkdf2 uses enc_type 0x01'
else
    fail "--kdf pbkdf2 enc_type is 0x$pbkdf_type, expected 0x01"
fi
if grep -qi 'PBKDF2' <<<"$pbkdf_stderr"; then
    pass '--kdf pbkdf2 message names PBKDF2'
else
    fail '--kdf pbkdf2 message does not name PBKDF2'
fi

mkdir pbkdf-out
if (cd pbkdf-out && "$zupt" x -p secret ../pbkdf.zupt >/dev/null 2>&1) &&
   cmp -s input.txt pbkdf-out/input.txt; then
    pass 'PBKDF2 archive roundtrips byte-exact'
else
    fail 'PBKDF2 archive roundtrips byte-exact'
fi
mkdir pbkdf-wrong
if (cd pbkdf-wrong && "$zupt" x -p wrong ../pbkdf.zupt >/dev/null 2>&1); then
    fail 'PBKDF2 archive rejects a wrong password'
else
    pass 'PBKDF2 archive rejects a wrong password'
fi

if ((sdk_enabled)); then
    "$zupt" c -p secret --kdf argon2id explicit.zupt input.txt >/dev/null 2>&1
    explicit_type=$(enc_type_of explicit.zupt)
    if [[ $explicit_type == 04 ]]; then
        pass '--kdf argon2id uses enc_type 0x04'
    else
        fail "--kdf argon2id enc_type is 0x$explicit_type, expected 0x04"
    fi
fi

if "$zupt" c -p secret --kdf invalid invalid.zupt input.txt >/dev/null 2>&1; then
    fail 'unknown --kdf value is rejected'
else
    pass 'unknown --kdf value is rejected'
fi

printf '\n  F-10 regression: %d passed, %d failed\n' "$passed" "$failed"
((failed == 0))
