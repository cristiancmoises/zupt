#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moises
#
# Key-file security regression coverage for the native ZKEY and ZPQK formats.

set -uo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
zupt_bin=${1:-$repo_root/zupt}
if [[ $zupt_bin != /* ]]; then
    zupt_bin=$(CDPATH='' cd -- "$(dirname -- "$zupt_bin")" 2>/dev/null && pwd -P)/$(basename -- "$zupt_bin")
fi
if [[ ! -x $zupt_bin ]]; then
    printf 'FAIL: executable not found: %s\n' "$zupt_bin" >&2
    exit 1
fi

test_root=$(mktemp -d "${TMPDIR:-/tmp}/zupt-key-files.XXXXXXXX") || exit 1
trap 'chmod -R u+rwX "$test_root" 2>/dev/null || true; rm -rf -- "$test_root"' EXIT HUP INT TERM

passes=0
failures=0
case_number=0

pass() {
    passes=$((passes + 1))
    printf '  PASS: %s\n' "$1"
}

fail() {
    failures=$((failures + 1))
    printf '  FAIL: %s\n' "$1" >&2
}

file_mode() {
    if stat -c '%a' "$1" >/dev/null 2>&1; then
        stat -c '%a' "$1"
    else
        stat -f '%Lp' "$1"
    fi
}

windows_private_acl() {
    local output=$1 windows_path
    command -v cygpath >/dev/null 2>&1 || return 1
    command -v powershell.exe >/dev/null 2>&1 || return 1
    windows_path=$(cygpath -aw -- "$output") || return 1
    # PowerShell variables must remain literal until powershell.exe evaluates
    # this single-quoted Bash argument.
    # shellcheck disable=SC2016
    ZUPT_KEY_ACL_PATH=$windows_path powershell.exe -NoLogo -NoProfile \
        -NonInteractive -Command '
            $ErrorActionPreference = "Stop"
            $acl = Get-Acl -LiteralPath $env:ZUPT_KEY_ACL_PATH
            $sidType = [System.Security.Principal.SecurityIdentifier]
            $rules = @($acl.GetAccessRules($true, $true, $sidType))
            $currentSid =
                [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if (-not $acl.AreAccessRulesProtected) {
                throw "private-key DACL permits inheritance"
            }
            if ($rules.Count -ne 1) {
                throw "private-key DACL does not contain exactly one ACE"
            }
            $rule = $rules[0]
            if ($rule.IsInherited) {
                throw "private-key ACE is inherited"
            }
            if ($rule.AccessControlType -ne
                    [System.Security.AccessControl.AccessControlType]::Allow) {
                throw "private-key ACE is not an allow rule"
            }
            if ($rule.IdentityReference.Value -ne $currentSid) {
                throw "private-key ACE is not restricted to the current user"
            }
            if ($rule.InheritanceFlags -ne
                    [System.Security.AccessControl.InheritanceFlags]::None -or
                $rule.PropagationFlags -ne
                    [System.Security.AccessControl.PropagationFlags]::None) {
                throw "private-key ACE unexpectedly propagates"
            }
            $fullControl = [int64](
                [System.Security.AccessControl.FileSystemRights]::FullControl)
            $actualRights = [int64]($rule.FileSystemRights)
            if (($actualRights -band $fullControl) -ne $fullControl) {
                throw "private-key ACE does not grant current-user full control"
            }
        ' </dev/null >/dev/null
}

generate_with_mode() {
    local label=$1 mask=$2 output=$3
    shift 3
    if (umask "$mask"; "$zupt_bin" keygen "$@" -o "$output" >/dev/null 2>&1); then
        case $(uname -s 2>/dev/null || printf unknown) in
            MINGW*|MSYS*|CYGWIN*)
                if windows_private_acl "$output"; then
                    pass "$label has a protected current-user-only DACL under umask $mask"
                else
                    fail "$label lacks a protected current-user-only DACL under umask $mask"
                fi
                ;;
            *)
                local mode
                mode=$(file_mode "$output")
                if [[ $mode == 600 ]]; then
                    pass "$label is mode 0600 under umask $mask"
                else
                    fail "$label mode under umask $mask is $mode, expected 600"
                fi
                ;;
        esac
    else
        fail "$label generation failed under umask $mask"
    fi
}

expect_generation_refused() {
    local label=$1 output=$2 expected=$3
    shift 3
    if "$zupt_bin" keygen "$@" -o "$output" >/dev/null 2>&1; then
        fail "$label unexpectedly replaced an existing destination"
    elif [[ -f $output && ! -L $output && $(<"$output") == "$expected" ]]; then
        pass "$label refuses an existing file without modifying it"
    else
        fail "$label changed or removed an existing file"
    fi
}

expect_symlink_refused() {
    local label=$1 link=$2 target=$3 expected=$4
    shift 4
    if "$zupt_bin" keygen "$@" -o "$link" >/dev/null 2>&1; then
        fail "$label unexpectedly followed an output symlink"
    elif [[ -L $link && -f $target && $(<"$target") == "$expected" ]]; then
        pass "$label refuses a symlink without modifying its target"
    else
        fail "$label changed the symlink or its target"
    fi
}

# Mutate a valid native key. Header-only mutations receive a newly calculated
# XXH64 so they prove the parser checks magic/version/flags/reserved/role rather
# than merely reaching the checksum rejection. XXH64 remains a corruption check,
# not authentication of an intentionally substituted public key.
mutate_key() {
    python3 - "$1" "$2" "$3" <<'PY'
import struct
import sys

MASK = (1 << 64) - 1
P1 = 11400714785074694791
P2 = 14029467366897019727
P3 = 1609587929392839161
P4 = 9650029242287828579
P5 = 2870177450012600261

def rol(value, bits):
    return ((value << bits) | (value >> (64 - bits))) & MASK

def round64(acc, value):
    acc = (acc + value * P2) & MASK
    acc = rol(acc, 31)
    return (acc * P1) & MASK

def merge_round(acc, value):
    acc ^= round64(0, value)
    return (acc * P1 + P4) & MASK

def xxh64(data, seed=0):
    length = len(data)
    pos = 0
    if length >= 32:
        v1 = (seed + P1 + P2) & MASK
        v2 = (seed + P2) & MASK
        v3 = seed & MASK
        v4 = (seed - P1) & MASK
        limit = length - 32
        while pos <= limit:
            v1 = round64(v1, struct.unpack_from('<Q', data, pos)[0]); pos += 8
            v2 = round64(v2, struct.unpack_from('<Q', data, pos)[0]); pos += 8
            v3 = round64(v3, struct.unpack_from('<Q', data, pos)[0]); pos += 8
            v4 = round64(v4, struct.unpack_from('<Q', data, pos)[0]); pos += 8
        result = rol(v1, 1) + rol(v2, 7) + rol(v3, 12) + rol(v4, 18)
        result &= MASK
        result = merge_round(result, v1)
        result = merge_round(result, v2)
        result = merge_round(result, v3)
        result = merge_round(result, v4)
    else:
        result = (seed + P5) & MASK

    result = (result + length) & MASK
    while pos + 8 <= length:
        lane = round64(0, struct.unpack_from('<Q', data, pos)[0])
        result ^= lane
        result = (rol(result, 27) * P1 + P4) & MASK
        pos += 8
    if pos + 4 <= length:
        result ^= (struct.unpack_from('<I', data, pos)[0] * P1) & MASK
        result = (rol(result, 23) * P2 + P3) & MASK
        pos += 4
    while pos < length:
        result ^= (data[pos] * P5) & MASK
        result = (rol(result, 11) * P1) & MASK
        pos += 1
    result ^= result >> 33
    result = (result * P2) & MASK
    result ^= result >> 29
    result = (result * P3) & MASK
    result ^= result >> 32
    return result & MASK

source, destination, mutation = sys.argv[1:]
data = bytearray(open(source, 'rb').read())
if len(data) < 16:
    raise SystemExit('source key is unexpectedly short')
stored = int.from_bytes(data[-8:], 'little')
if stored != xxh64(data[:-8]):
    raise SystemExit('source key checksum does not match the format')

recheck = False
if mutation == 'magic':
    data[0] ^= 0x20
    recheck = True
elif mutation == 'version':
    data[4] = 2
    recheck = True
elif mutation == 'flag':
    data[5] = 0x80
    recheck = True
elif mutation == 'reserved':
    data[6] = 1
    recheck = True
elif mutation == 'role':
    data[5] ^= 1
    recheck = True
elif mutation == 'key':
    data[16] ^= 1
elif mutation == 'secret':
    if data[5] != 1:
        raise SystemExit('secret mutation requires a private key')
    data[-16] ^= 1
elif mutation == 'checksum':
    data[-1] ^= 1
elif mutation == 'truncated':
    del data[-1]
elif mutation == 'appended':
    data.append(0x41)
else:
    raise SystemExit('unknown mutation: ' + mutation)

if recheck:
    data[-8:] = xxh64(data[:-8]).to_bytes(8, 'little')
open(destination, 'wb').write(data)
PY
}

expect_public_rejected() {
    local format=$1 option=$2 key=$3 label=$4
    case_number=$((case_number + 1))
    local archive=$test_root/rejected-public-$case_number.zupt
    if "$zupt_bin" compress "$option" "$key" "$archive" \
            "$test_root/input.txt" >/dev/null 2>&1; then
        fail "$format public key accepts $label"
    elif [[ -e $archive ]]; then
        fail "$format public key rejection published an archive for $label"
    else
        pass "$format public key rejects $label"
    fi
}

expect_private_rejected() {
    local format=$1 key=$2 label=$3
    case_number=$((case_number + 1))
    local public=$test_root/rejected-private-$case_number.pub
    if [[ $format == ZKEY ]]; then
        if "$zupt_bin" keygen --pub -o "$public" -k "$key" >/dev/null 2>&1; then
            fail "$format private key accepts $label"
            return
        fi
    else
        if "$zupt_bin" keygen --pub --pq-only -o "$public" -k "$key" \
                >/dev/null 2>&1; then
            fail "$format private key accepts $label"
            return
        fi
    fi
    if [[ -e $public ]]; then
        fail "$format private key rejection published output for $label"
    else
        pass "$format private key rejects $label"
    fi
}

printf 'key-file security regression input\n' >"$test_root/input.txt"

printf 'Key-file permissions and no-replace publication\n'
generate_with_mode 'ZKEY private key' 022 "$test_root/hybrid-022.key"
generate_with_mode 'ZKEY private key' 000 "$test_root/hybrid-000.key"
generate_with_mode 'ZPQK private key' 022 "$test_root/pq-022.key" --pq-only
generate_with_mode 'ZPQK private key' 000 "$test_root/pq-000.key" --pq-only

printf 'hybrid sentinel' >"$test_root/existing-hybrid.key"
expect_generation_refused 'ZKEY generation' "$test_root/existing-hybrid.key" \
    'hybrid sentinel'
printf 'pq sentinel' >"$test_root/existing-pq.key"
expect_generation_refused 'ZPQK generation' "$test_root/existing-pq.key" \
    'pq sentinel' --pq-only

if ln -s "$test_root/hybrid-target" "$test_root/hybrid-link" 2>/dev/null; then
    printf 'hybrid target sentinel' >"$test_root/hybrid-target"
    expect_symlink_refused 'ZKEY generation' "$test_root/hybrid-link" \
        "$test_root/hybrid-target" 'hybrid target sentinel'
else
    printf '  SKIP: symlinks unavailable for ZKEY no-follow test\n'
fi
if ln -s "$test_root/pq-target" "$test_root/pq-link" 2>/dev/null; then
    printf 'pq target sentinel' >"$test_root/pq-target"
    expect_symlink_refused 'ZPQK generation' "$test_root/pq-link" \
        "$test_root/pq-target" 'pq target sentinel' --pq-only
else
    printf '  SKIP: symlinks unavailable for ZPQK no-follow test\n'
fi

cp "$test_root/hybrid-022.key" "$test_root/hybrid-before-same-path.key"
if "$zupt_bin" keygen --pub -o "$test_root/hybrid-022.key" \
        -k "$test_root/hybrid-022.key" >/dev/null 2>&1; then
    fail 'ZKEY public export accepted the private input as its output path'
elif cmp -s "$test_root/hybrid-before-same-path.key" \
        "$test_root/hybrid-022.key"; then
    pass 'ZKEY same-path public export preserves the private key'
else
    fail 'ZKEY same-path public export modified the private key'
fi

cp "$test_root/pq-022.key" "$test_root/pq-before-same-path.key"
if "$zupt_bin" keygen --pub --pq-only -o "$test_root/pq-022.key" \
        -k "$test_root/pq-022.key" >/dev/null 2>&1; then
    fail 'ZPQK public export accepted the private input as its output path'
elif cmp -s "$test_root/pq-before-same-path.key" "$test_root/pq-022.key"; then
    pass 'ZPQK same-path public export preserves the private key'
else
    fail 'ZPQK same-path public export modified the private key'
fi

printf '\nValid key workflows\n'
if "$zupt_bin" keygen --pub -o "$test_root/hybrid.pub" \
        -k "$test_root/hybrid-022.key" >/dev/null 2>&1 &&
   "$zupt_bin" compress --pq "$test_root/hybrid.pub" \
        "$test_root/hybrid.zupt" "$test_root/input.txt" >/dev/null 2>&1 &&
   "$zupt_bin" extract --pq "$test_root/hybrid-022.key" \
        -o "$test_root/hybrid-out" "$test_root/hybrid.zupt" >/dev/null 2>&1 &&
   hybrid_extracted=$(find "$test_root/hybrid-out" -name input.txt -type f \
        -print -quit) && [[ -n $hybrid_extracted ]] &&
   cmp -s "$test_root/input.txt" "$hybrid_extracted"; then
    pass 'valid ZKEY public/private round trip'
else
    fail 'valid ZKEY public/private round trip'
fi

if "$zupt_bin" keygen --pub --pq-only -o "$test_root/pq.pub" \
        -k "$test_root/pq-022.key" >/dev/null 2>&1 &&
   "$zupt_bin" compress --pq-only "$test_root/pq.pub" \
        "$test_root/pq.zupt" "$test_root/input.txt" >/dev/null 2>&1 &&
   "$zupt_bin" extract --pq-only "$test_root/pq-022.key" \
        -o "$test_root/pq-out" "$test_root/pq.zupt" >/dev/null 2>&1 &&
   pq_extracted=$(find "$test_root/pq-out" -name input.txt -type f \
        -print -quit) && [[ -n $pq_extracted ]] &&
   cmp -s "$test_root/input.txt" "$pq_extracted"; then
    pass 'valid ZPQK public/private round trip'
else
    fail 'valid ZPQK public/private round trip'
fi

# Compatibility: native readers historically allowed the private file itself
# wherever a public recipient key was accepted.
if "$zupt_bin" compress --pq "$test_root/hybrid-022.key" \
        "$test_root/hybrid-private-recipient.zupt" "$test_root/input.txt" \
        >/dev/null 2>&1; then
    pass 'valid private ZKEY remains accepted as recipient input'
else
    fail 'valid private ZKEY recipient compatibility'
fi
if "$zupt_bin" compress --pq-only "$test_root/pq-022.key" \
        "$test_root/pq-private-recipient.zupt" "$test_root/input.txt" \
        >/dev/null 2>&1; then
    pass 'valid private ZPQK remains accepted as recipient input'
else
    fail 'valid private ZPQK recipient compatibility'
fi

printf '\nMalformed native key rejection\n'
metadata_mutations=(magic version flag reserved role key checksum truncated appended)
for mutation in "${metadata_mutations[@]}"; do
    hybrid_bad=$test_root/hybrid-public-$mutation.key
    if mutate_key "$test_root/hybrid.pub" "$hybrid_bad" "$mutation"; then
        expect_public_rejected ZKEY --pq "$hybrid_bad" "$mutation"
    else
        fail "could not create ZKEY public mutation: $mutation"
    fi

    pq_bad=$test_root/pq-public-$mutation.key
    if mutate_key "$test_root/pq.pub" "$pq_bad" "$mutation"; then
        expect_public_rejected ZPQK --pq-only "$pq_bad" "$mutation"
    else
        fail "could not create ZPQK public mutation: $mutation"
    fi
done

private_mutations=(magic version flag reserved role key secret checksum truncated appended)
for mutation in "${private_mutations[@]}"; do
    hybrid_bad=$test_root/hybrid-private-$mutation.key
    if mutate_key "$test_root/hybrid-022.key" "$hybrid_bad" "$mutation"; then
        expect_private_rejected ZKEY "$hybrid_bad" "$mutation"
    else
        fail "could not create ZKEY private mutation: $mutation"
    fi

    pq_bad=$test_root/pq-private-$mutation.key
    if mutate_key "$test_root/pq-022.key" "$pq_bad" "$mutation"; then
        expect_private_rejected ZPQK "$pq_bad" "$mutation"
    else
        fail "could not create ZPQK private mutation: $mutation"
    fi
done

printf '\nKey-file results: %d passed, %d failed\n' "$passes" "$failures"
((failures == 0))
