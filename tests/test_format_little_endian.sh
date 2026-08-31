#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
bin=${1:-$repo_root/zupt}
case "$bin" in
    /*) ;;
    *) bin="$(pwd -P)/${bin#./}" ;;
esac

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

test -x "$bin" || fail "$bin is not executable"
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'

tmp=$(mktemp -d "${TMPDIR:-/tmp}/zupt-format-le.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
printf 'little-endian format fixture\n' > "$tmp/input"
printf 'format-test-password\n' > "$tmp/password"
chmod 600 "$tmp/password"

"$bin" compress --store --kdf pbkdf2 --pass-file "$tmp/password" \
    "$tmp/format.zupt" "$tmp/input" >/dev/null 2>&1 ||
    fail 'could not create PBKDF2 archive fixture'

python3 - "$tmp/format.zupt" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
data = path.read_bytes()

def reject(message):
    raise SystemExit(f"FAIL: {message}")

def varint(offset):
    value = 0
    shift = 0
    start = offset
    while offset < len(data) and shift <= 63:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte & 0x80 == 0:
            encoded = data[start:offset]
            canonical = bytearray()
            remaining = value
            while remaining >= 0x80:
                canonical.append((remaining & 0x7f) | 0x80)
                remaining >>= 7
            canonical.append(remaining)
            if bytes(canonical) != encoded:
                reject("non-canonical varint in generated archive")
            return value, offset
        shift += 7
    reject("unterminated varint")

if len(data) < 64 + 32 + 32:
    reject("archive is too small")
if data[:6] != b"ZUPT\x1a\x00" or data[6:8] != bytes((1, 6)):
    reject("header magic/version mismatch")

flags = struct.unpack_from("<I", data, 8)[0]
if data[8:12] != flags.to_bytes(4, "little"):
    reject("global flags are not little-endian")
required = (1 << 0) | (1 << 8) | (1 << 9)
if flags & required != required:
    reject("encrypted AAD policy flags are missing")

creation = struct.unpack_from("<Q", data, 12)[0]
if data[12:20] != creation.to_bytes(8, "little"):
    reject("creation time is not little-endian")
enc_offset = struct.unpack_from("<Q", data, 36)[0]
if enc_offset != 64 or data[36:44] != enc_offset.to_bytes(8, "little"):
    reject("encryption-header offset is not canonical little-endian")

offset = enc_offset
if data[offset:offset + 3] != b"\xbb\x01\x03":
    reject("encryption-header frame is missing")
codec, block_flags = struct.unpack_from("<HH", data, offset + 3)
if codec != 0 or block_flags != 0:
    reject("encryption-header frame metadata is invalid")
offset += 7
plain_size, offset = varint(offset)
payload_size, offset = varint(offset)
offset += 8
if plain_size != 53 or payload_size != 53 or data[offset] != 0x01:
    reject("PBKDF2 header layout is invalid")
iterations = struct.unpack_from("<I", data, offset + 49)[0]
if iterations != 600000:
    reject("PBKDF2 iteration count is not canonical little-endian")

footer_offset = len(data) - 64
index_offset, total_blocks, archive_checksum = struct.unpack_from(
    "<QQQ", data, footer_offset
)
if data[footer_offset + 24:footer_offset + 28] != b"ZEND":
    reject("footer magic is missing")
if data[footer_offset + 28:footer_offset + 32] != (1).to_bytes(4, "little"):
    reject("footer version is not little-endian")
if not (64 < index_offset < footer_offset):
    reject("footer index offset is outside the archive")
if data[index_offset:index_offset + 3] != b"\xbb\x01\x02":
    reject("footer does not point to the index frame")
for value, start in (
    (index_offset, footer_offset),
    (total_blocks, footer_offset + 8),
    (archive_checksum, footer_offset + 16),
):
    if data[start:start + 8] != value.to_bytes(8, "little"):
        reject("footer scalar is not little-endian")

print("portable little-endian header/footer/KDF serialization: PASS")
PY

# Exercise the C stream decoder with wire encodings that previously wrapped or
# admitted two representations of the same scalar.  Strip the AIT deliberately
# and use the explicit legacy switch so rejection comes from the block parser,
# not from the trailer policy.
printf 'x' > "$tmp/one-byte"
"$bin" compress --store "$tmp/varint-base.zupt" "$tmp/one-byte" \
    >/dev/null 2>&1 || fail 'could not create varint fixture'
python3 - "$tmp/varint-base.zupt" "$tmp" <<'PY'
import pathlib
import struct
import sys

source = pathlib.Path(sys.argv[1]).read_bytes()
out = pathlib.Path(sys.argv[2])
if len(source) < 128 or source[64:67] != b"\xbb\x01\x00":
    raise SystemExit("FAIL: unexpected varint fixture layout")

footer = len(source) - 64
index_offset = struct.unpack_from("<Q", source, footer)[0]
varint_offset = 64 + 7
if source[varint_offset] != 1:
    raise SystemExit("FAIL: fixture size does not use a one-byte varint")

def write_mutation(name, replacement):
    # Discard the 32-byte integrity trailer, expand the first size field, and
    # keep the legacy footer's index pointer structurally consistent.
    changed = bytearray(source[:-32])
    changed[varint_offset:varint_offset + 1] = replacement
    delta = len(replacement) - 1
    changed_footer = footer + delta
    struct.pack_into("<Q", changed, changed_footer, index_offset + delta)
    (out / name).write_bytes(changed)

write_mutation("varint-overlong.zupt", b"\x81\x00")
write_mutation("varint-overflow.zupt", b"\x81" + b"\x80" * 8 + b"\x02")
PY

for malformed in "$tmp/varint-overlong.zupt" "$tmp/varint-overflow.zupt"; do
    if "$bin" test --allow-legacy-no-ait "$malformed" >/dev/null 2>&1; then
        fail "non-canonical or overflowing varint was accepted: ${malformed##*/}"
    fi
done
printf 'non-canonical and overflowing uint64 varints: PASS\n'
