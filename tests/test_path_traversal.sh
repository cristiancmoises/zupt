#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Extraction confinement and atomic-output regression tests.

set -Eeuo pipefail

REPO_ROOT=$(pwd -P)
ZUPT_BIN=${1:-$REPO_ROOT/zupt}
case $ZUPT_BIN in
    /*) ;;
    *) ZUPT_BIN=$REPO_ROOT/${ZUPT_BIN#./} ;;
esac
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/zupt-path-traversal.XXXXXX")
cleanup() {
    local status=$?
    chmod -R u+rwX "$TEST_ROOT" 2>/dev/null || true
    rm -rf -- "$TEST_ROOT"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

PASS=0
FAIL=0
SKIP=0
pass() { printf '  PASS: %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL: %s\n' "$1"; FAIL=$((FAIL + 1)); }
skip() { printf '  SKIP: %s\n' "$1"; SKIP=$((SKIP + 1)); }
WINDOWS_NATIVE=0
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) WINDOWS_NATIVE=1 ;;
esac

FIXTURE=$TEST_ROOT/archive-path-fixture
# Compiler and linker flag variables intentionally expand into argument lists,
# matching the Makefile command-line contract.
# shellcheck disable=SC2086
"${CC:-cc}" ${CPPFLAGS:-} ${CFLAGS:-} -std=c11 -I"$REPO_ROOT/include" \
    "$REPO_ROOT/tests/archive_path_fixture.c" "$REPO_ROOT/src/zupt_xxh.c" \
    ${LDFLAGS:-} ${LDLIBS:-} -o "$FIXTURE"

make_fixture() {
    MSYS2_ARG_CONV_EXCL='--entry=' "$FIXTURE" "$1" "--entry=$2"
    # Prove that the archive passed header, trailer, index-block, index checksum,
    # decompression, and index parsing before using it as a negative fixture.
    "$ZUPT_BIN" list "$1" > "$TEST_ROOT/list.log" 2>&1
    grep -F -- "$2" "$TEST_ROOT/list.log" >/dev/null
}

expect_unsafe_path() {
    local label=$1 archive=$2 entry=$3 output=$4 log=$TEST_ROOT/extract.log rc
    make_fixture "$archive" "$entry"
    mkdir -p "$output"
    set +e
    "$ZUPT_BIN" extract -o "$output" "$archive" > "$log" 2>&1
    rc=$?
    set -e
    if ((rc != 0)) && grep -F 'rejected unsafe path' "$log" >/dev/null; then
        pass "$label"
    else
        fail "$label"
    fi
}

cd "$TEST_ROOT"

expect_unsafe_path 'relative .. entry is rejected after a valid index parse' \
    "$TEST_ROOT/relative.zupt" '../escaped.txt' "$TEST_ROOT/relative-out"
[[ ! -e $TEST_ROOT/escaped.txt ]] || fail 'relative traversal wrote outside root'

ABSOLUTE_TARGET=$TEST_ROOT/absolute-owned
expect_unsafe_path 'absolute entry is rejected after a valid index parse' \
    "$TEST_ROOT/absolute.zupt" "$ABSOLUTE_TARGET" "$TEST_ROOT/absolute-out"
if [[ ! -e $ABSOLUTE_TARGET ]]; then
    pass 'absolute target remains absent'
else
    fail 'absolute target remains absent'
fi

for case_data in \
    'trailing-space|dir/.. ' \
    'alternate-data-stream|dir/name:stream' \
    'reserved-device|dir/CON' \
    'reserved-device-extension|dir/LPT1.txt' \
    'trailing-dot|dir/file.'; do
    label=${case_data%%|*}
    entry=${case_data#*|}
    expect_unsafe_path "Windows-normalized $label path is rejected" \
        "$TEST_ROOT/$label.zupt" "$entry" "$TEST_ROOT/$label-out"
done

control_entry=$'safe\033[31mRED\033[0m.txt'
MSYS2_ARG_CONV_EXCL='--entry=' "$FIXTURE" "$TEST_ROOT/control.zupt" \
    "--entry=$control_entry"
set +e
"$ZUPT_BIN" list "$TEST_ROOT/control.zupt" \
    > "$TEST_ROOT/control.log" 2>&1
control_status=$?
set -e
if ((control_status != 0)) && ! grep -q $'\033' "$TEST_ROOT/control.log"; then
    pass 'control-byte archive path is rejected without terminal injection'
else
    fail 'control-byte archive path is rejected without terminal injection'
fi

file_contains_hex_bytes() {
    python3 - "$1" "$2" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
needle = bytes.fromhex(sys.argv[2])
raise SystemExit(0 if needle in data else 1)
PY
}

expect_display_unsafe_hex_path_rejected() {
    local label=$1 name=$2 entry_hex=$3 forbidden_hex=$4
    local archive=$TEST_ROOT/$name.zupt log=$TEST_ROOT/$name.log status
    MSYS2_ARG_CONV_EXCL='--entry-hex=' \
        "$FIXTURE" "$archive" "--entry-hex=$entry_hex"
    if ! file_contains_hex_bytes "$archive" "$entry_hex"; then
        printf '  fixture did not preserve the requested path bytes: %s\n' \
            "$entry_hex" >&2
        fail "$label"
        return
    fi
    set +e
    "$ZUPT_BIN" list "$archive" > "$log" 2>&1
    status=$?
    set -e
    if ((status != 0)) && ! file_contains_hex_bytes "$log" "$forbidden_hex"; then
        pass "$label"
    else
        fail "$label"
    fi
}

if MSYS2_ARG_CONV_EXCL='--entry-hex=' \
       "$FIXTURE" "$TEST_ROOT/invalid-hex.zupt" '--entry-hex=0' \
       >/dev/null 2>&1 ||
   MSYS2_ARG_CONV_EXCL='--entry-hex=' \
       "$FIXTURE" "$TEST_ROOT/invalid-hex.zupt" '--entry-hex=GG' \
       >/dev/null 2>&1; then
    fail 'archive path fixture rejects malformed hex input'
else
    pass 'archive path fixture rejects malformed hex input'
fi

expect_display_unsafe_hex_path_rejected \
    'raw C1 archive path is rejected without terminal injection' \
    raw-c1 736166659b33316d2e747874 9b
expect_display_unsafe_hex_path_rejected \
    'UTF-8 C1 archive path is rejected without terminal injection' \
    utf8-c1 73616665c29b33316d2e747874 c29b
expect_display_unsafe_hex_path_rejected \
    'Unicode bidi-control archive path is rejected without display spoofing' \
    bidi 73616665e280ae6578652e747874 e280ae
expect_display_unsafe_hex_path_rejected \
    'invalid UTF-8 archive path is rejected without raw display' \
    invalid-utf8 73616665c0af2e747874 c0af

make_fixture "$TEST_ROOT/leaf.zupt" 'innocent.txt'
printf '%s\n' DO_NOT_OVERWRITE > "$TEST_ROOT/sentinel"
mkdir "$TEST_ROOT/leaf-out"
if ln -s "$TEST_ROOT/sentinel" "$TEST_ROOT/leaf-out/innocent.txt" \
        2>/dev/null && [[ -L $TEST_ROOT/leaf-out/innocent.txt ]]; then
    if ! "$ZUPT_BIN" extract -o "$TEST_ROOT/leaf-out" "$TEST_ROOT/leaf.zupt" \
            > "$TEST_ROOT/leaf.log" 2>&1 &&
       [[ $(<"$TEST_ROOT/sentinel") == DO_NOT_OVERWRITE ]]; then
        pass 'leaf symlink is refused without changing its target'
    else
        fail 'leaf symlink is refused without changing its target'
    fi
else
    skip 'leaf symlink test is unsupported by this runner'
fi

mkdir "$TEST_ROOT/regular-out"
printf '%s\n' EXISTING > "$TEST_ROOT/regular-out/innocent.txt"
if ! "$ZUPT_BIN" extract -o "$TEST_ROOT/regular-out" "$TEST_ROOT/leaf.zupt" \
        > "$TEST_ROOT/regular.log" 2>&1 &&
   [[ $(<"$TEST_ROOT/regular-out/innocent.txt") == EXISTING ]]; then
    pass 'existing regular file is never overwritten'
else
    fail 'existing regular file is never overwritten'
fi

mkdir "$TEST_ROOT/hardlink-out"
printf '%s\n' HARDLINK_SENTINEL > "$TEST_ROOT/hardlink-target"
if ln "$TEST_ROOT/hardlink-target" "$TEST_ROOT/hardlink-out/innocent.txt" 2>/dev/null; then
    if ! "$ZUPT_BIN" extract -o "$TEST_ROOT/hardlink-out" "$TEST_ROOT/leaf.zupt" \
            > "$TEST_ROOT/hardlink.log" 2>&1 &&
       [[ $(<"$TEST_ROOT/hardlink-target") == HARDLINK_SENTINEL ]]; then
        pass 'existing hardlink is never overwritten'
    else
        fail 'existing hardlink is never overwritten'
    fi
else
    skip 'hardlink test is unsupported by the temporary filesystem'
fi

make_fixture "$TEST_ROOT/parent.zupt" 'nested/file.txt'
mkdir "$TEST_ROOT/parent-out" "$TEST_ROOT/parent-outside"
if ln -s "$TEST_ROOT/parent-outside" "$TEST_ROOT/parent-out/nested" \
        2>/dev/null && [[ -L $TEST_ROOT/parent-out/nested ]]; then
    if ! "$ZUPT_BIN" extract -o "$TEST_ROOT/parent-out" "$TEST_ROOT/parent.zupt" \
            > "$TEST_ROOT/parent.log" 2>&1 &&
       [[ -z $(find "$TEST_ROOT/parent-outside" -mindepth 1 -print -quit) ]]; then
        pass 'intermediate symlink cannot redirect extraction or directory creation'
    else
        fail 'intermediate symlink cannot redirect extraction or directory creation'
    fi
else
    skip 'intermediate symlink test is unsupported by this runner'
fi

mkdir "$TEST_ROOT/root-outside"
if ln -s "$TEST_ROOT/root-outside" "$TEST_ROOT/root-link" 2>/dev/null &&
        [[ -L $TEST_ROOT/root-link ]]; then
    if ((WINDOWS_NATIVE)); then
        if ! "$ZUPT_BIN" extract -o "$TEST_ROOT/root-link/child" \
                "$TEST_ROOT/leaf.zupt" > "$TEST_ROOT/root-link.log" 2>&1 &&
           [[ -z $(find "$TEST_ROOT/root-outside" -mindepth 1 -print -quit) ]]; then
            pass 'Windows rejects a reparse-point output-root ancestor'
        else
            fail 'Windows rejects a reparse-point output-root ancestor'
        fi
    elif "$ZUPT_BIN" extract -o "$TEST_ROOT/root-link/child" \
            "$TEST_ROOT/leaf.zupt" > "$TEST_ROOT/root-link.log" 2>&1 &&
         [[ $(<"$TEST_ROOT/root-outside/child/innocent.txt") == 'fixture content' ]]; then
        pass 'user-selected POSIX output-root symlink is resolved once'
    else
        fail 'user-selected POSIX output-root symlink is resolved once'
    fi
else
    skip 'output-root symlink test is unsupported by this runner'
fi

make_fixture "$TEST_ROOT/backslash.zupt" 'back\slash.txt'
mkdir "$TEST_ROOT/backslash-out"
if "$ZUPT_BIN" extract -o "$TEST_ROOT/backslash-out" "$TEST_ROOT/backslash.zupt" \
        > "$TEST_ROOT/backslash.log" 2>&1 &&
   [[ -f $TEST_ROOT/backslash-out/back/slash.txt ]]; then
    pass 'backslash separators are normalized within the extraction root'
else
    fail 'backslash separators are normalized within the extraction root'
fi

make_fixture "$TEST_ROOT/legitimate.zupt" 'safe dir/ação.txt'
mkdir "$TEST_ROOT/legitimate-out"
if "$ZUPT_BIN" extract -o "$TEST_ROOT/legitimate-out" \
        "$TEST_ROOT/legitimate.zupt" > "$TEST_ROOT/legitimate.log" 2>&1 &&
   [[ $(<"$TEST_ROOT/legitimate-out/safe dir/ação.txt") == 'fixture content' ]]; then
    pass 'safe nested UTF-8 path extracts normally'
else
    fail 'safe nested UTF-8 path extracts normally'
fi

mkdir -p "$TEST_ROOT/relative-root/work"
if (cd "$TEST_ROOT/relative-root/work" &&
    "$ZUPT_BIN" extract -o ../restore "$TEST_ROOT/leaf.zupt" \
        > "$TEST_ROOT/relative-root.log" 2>&1) &&
   [[ -f $TEST_ROOT/relative-root/restore/innocent.txt ]]; then
    pass 'user-selected output root may contain a relative .. component'
else
    fail 'user-selected output root may contain a relative .. component'
fi

cp "$TEST_ROOT/leaf.zupt" "$TEST_ROOT/corrupt.zupt"
python3 - "$TEST_ROOT/corrupt.zupt" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = bytearray(path.read_bytes())
# Header (64) + data-block fixed/varint header (17): first payload byte.
data[81] ^= 0x01
path.write_bytes(data)
PY
mkdir "$TEST_ROOT/corrupt-out"
if ! "$ZUPT_BIN" extract -o "$TEST_ROOT/corrupt-out" "$TEST_ROOT/corrupt.zupt" \
        > "$TEST_ROOT/corrupt.log" 2>&1 &&
   [[ -z $(find "$TEST_ROOT/corrupt-out" -mindepth 1 -print -quit) ]]; then
    pass 'corrupt payload leaves neither a final nor temporary output file'
else
    fail 'corrupt payload leaves neither a final nor temporary output file'
fi

printf '\n  Path-confinement regression: %d PASS, %d FAIL, %d SKIP\n' \
    "$PASS" "$FAIL" "$SKIP"
((FAIL == 0))
