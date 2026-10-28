#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -Eeuo pipefail

# Preserve real byte-count output before faulting only extracted-file counts.
if [[ ${SOURCE_AUDIT_BYTE_CHILD:-0} == 1 ]]; then
    if [[ $# != 1 || $1 != -c ]]; then
        exec "$SOURCE_AUDIT_REAL_WC" "$@"
    fi
    printf '%s\n' "$SOURCE_AUDIT_BYTE_MODE" >>"$SOURCE_AUDIT_BYTE_LOG"
    if byte_count=$("$SOURCE_AUDIT_REAL_WC" "$@"); then
        :
    else
        printf 'BYTE-COUNT-SETUP-FAIL: real producer failed\n' >&2
        exit 125
    fi
    if [[ ! $byte_count =~ ^[[:space:]]*[0-9]+[[:space:]]*$ ]]; then
        printf 'BYTE-COUNT-SETUP-FAIL: invalid real count\n' >&2
        exit 125
    fi
    byte_count=${byte_count//[[:space:]]/}
    printf 'BYTE-COUNT-REAL: %s\n' "$byte_count" >&2
    case $SOURCE_AUDIT_BYTE_MODE in
        pass) printf '%s\n' "$byte_count"; exit 0 ;;
        empty) ;;
        zero) printf '0\n' ;;
        complete) printf '%s\n' "$byte_count" ;;
        *) exit 125 ;;
    esac
    printf 'BYTE-COUNT-PRODUCER-FAULT: %s\n' "$SOURCE_AUDIT_BYTE_MODE" >&2
    exit 73
fi

# Fault only the selected enumeration boundary, after the real tool succeeds.
if [[ ${SOURCE_AUDIT_ENUM_CHILD:-0} == 1 ]]; then
    enum_tool=${0##*/}
    case $enum_tool in
        find) enum_real=$SOURCE_AUDIT_REAL_FIND ;;
        git) enum_real=$SOURCE_AUDIT_REAL_GIT ;;
        *) exit 125 ;;
    esac
    case "$SOURCE_AUDIT_ENUM_SCOPE:$enum_tool:${3:-}" in
        tree:find:-path|expanded:find:-type|index:git:ls-files) ;;
        *) exec "$enum_real" "$@" ;;
    esac
    printf '%s %s\n' "$SOURCE_AUDIT_ENUM_SCOPE" "$SOURCE_AUDIT_ENUM_MODE" \
        >>"$SOURCE_AUDIT_ENUM_LOG"
    if [[ $SOURCE_AUDIT_ENUM_MODE == pass ]]; then
        exec "$enum_real" "$@"
    fi
    enum_list=$(mktemp "${TMPDIR:-/tmp}/zupt-enumeration-fixture.XXXXXXXX")
    trap 'rm -f -- "$enum_list"' EXIT
    if ! "$enum_real" "$@" >"$enum_list"; then
        printf 'ENUMERATION-SETUP-FAIL: real producer failed\n' >&2
        exit 125
    fi
    case $SOURCE_AUDIT_ENUM_MODE in
        empty) ;;
        partial)
            enum_found=0
            while IFS= read -r -d '' enum_record; do
                case "$enum_tool:$enum_record" in
                    find:*/source.c|git:*$'\t'source.c)
                        printf '%s\0' "$enum_record"
                        enum_found=1
                        break ;;
                esac
            done <"$enum_list"
            if ((enum_found != 1)); then
                printf 'ENUMERATION-SETUP-FAIL: safe record missing\n' >&2
                exit 125
            fi
            ;;
        *) exit 125 ;;
    esac
    printf 'ENUMERATION-PRODUCER-FAULT: %s %s\n' \
        "$SOURCE_AUDIT_ENUM_SCOPE" "$SOURCE_AUDIT_ENUM_MODE" >&2
    exit 73
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
SCANNER=$ROOT/scripts/check-source-only.sh
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/zupt-source-only-tests.XXXXXXXX")
PASSED=0

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$TEST_TMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

pass() {
    PASSED=$((PASSED + 1))
    printf 'ok %d - %s\n' "$PASSED" "$1"
}

skip() {
    PASSED=$((PASSED + 1))
    printf 'ok %d - %s # SKIP\n' "$PASSED" "$1"
}

expect_pass_tree() {
    local name=$1 tree=$2 output=$TEST_TMP/output
    if "$SCANNER" --tree "$tree" >"$output" 2>&1 && grep -q '^PASS source-only:' "$output"; then
        pass "$name"
    else
        printf 'not ok - %s\n' "$name"
        sed -n '1,120p' "$output"
        exit 1
    fi
}

expect_fail_tree() {
    local name=$1 tree=$2 expected=${3:-} output=$TEST_TMP/output
    if "$SCANNER" --tree "$tree" >"$output" 2>&1; then
        printf 'not ok - %s (scanner unexpectedly passed)\n' "$name"
        exit 1
    fi
    grep -q '^FAIL ' "$output" || {
        printf 'not ok - %s (missing FAIL finding)\n' "$name"
        exit 1
    }
    grep -q '^FAIL source-only:' "$output" || {
        printf 'not ok - %s (missing FAIL summary)\n' "$name"
        exit 1
    }
    if [[ -n $expected ]] && ! grep -Fq -- "$expected" "$output"; then
        printf 'not ok - %s (missing expected path)\n' "$name"
        sed -n '1,120p' "$output"
        exit 1
    fi
    pass "$name"
}

expect_fail_archive_with_limits() {
    local name=$1 archive=$2 expected=$3
    shift 3
    local output=$TEST_TMP/output
    if env "$@" "$SCANNER" --archive "$archive" >"$output" 2>&1; then
        printf 'not ok - %s (scanner unexpectedly passed)\n' "$name"
        exit 1
    fi
    if ! grep -Fq -- "$expected" "$output"; then
        printf 'not ok - %s (missing expected bounded-archive finding)\n' "$name"
        sed -n '1,120p' "$output"
        exit 1
    fi
    pass "$name"
}

fresh_tree() {
    local name=$1
    mkdir -p "$TEST_TMP/$name"
    printf '%s' "$TEST_TMP/$name"
}

safe=$(fresh_tree safe)
mkdir -p "$safe/src" "$safe/assets"
printf '#include <stdio.h>\nint main(void) { return 0; }\n' >"$safe/src/main.c"
printf '.text\n.globl portable_symbol\nportable_symbol:\n  ret\n' >"$safe/src/portable.S"
printf '\211PNG\r\n\032\n' >"$safe/assets/icon.png"
printf '\000\000\001\000' >"$safe/assets/icon.ico"
if ln -s src/main.c "$safe/main-link.c" 2>/dev/null &&
        [[ -L $safe/main-link.c ]]; then
    SYMLINKS_SUPPORTED=1
    safe_label='text source, assembly, PNG, ICO, and internal symlink pass'
else
    SYMLINKS_SUPPORTED=0
    safe_label='text source, assembly, PNG, and ICO pass (symlink unavailable)'
fi
expect_pass_tree "$safe_label" "$safe"

tree=$(fresh_tree undeclared-bin)
printf '\001\002\003fixture data\n' >"$tree/vector.bin"
expect_fail_tree 'undeclared .bin data is rejected' "$tree" vector.bin

tree=$(fresh_tree declared-bin)
mkdir -p "$tree/tests/data"
printf '\001\002\003fixture data\n' >"$tree/tests/data/vector.bin"
manifest=$TEST_TMP/source-data.tsv
printf 'tests/data/vector.bin\ttest vector\tgenerated by test_source_only.sh\tAGPL-3.0-or-later\n' >"$manifest"
if "$SCANNER" --data-manifest "$manifest" --tree "$tree" >"$TEST_TMP/output" 2>&1 &&
   grep -q '^PASS source-only:' "$TEST_TMP/output"; then
    pass 'declared non-executable .bin fixture passes with complete metadata'
else
    printf 'not ok - declared non-executable .bin fixture passes\n'
    sed -n '1,120p' "$TEST_TMP/output"
    exit 1
fi

printf '\177ELF\002\001\001\000compiled' >"$tree/tests/data/vector.bin"
if "$SCANNER" --data-manifest "$manifest" --tree "$tree" >"$TEST_TMP/output" 2>&1; then
    printf 'not ok - manifest cannot allow executable magic\n'
    exit 1
elif grep -Fq 'tests/data/vector.bin' "$TEST_TMP/output"; then
    pass 'data manifest cannot exempt executable magic'
else
    printf 'not ok - executable magic path missing from manifest test\n'
    exit 1
fi

tree=$(fresh_tree elf)
printf '\177ELF\002\001\001\000compiled' >"$tree/renamed.txt"
expect_fail_tree 'ELF renamed as text is rejected' "$tree" renamed.txt

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        skip 'control-byte filenames are forbidden by the Windows filesystem'
        skip 'raw C1 filenames are forbidden by the Windows filesystem'
        skip 'UTF-8 C1 filenames are forbidden by the Windows filesystem'
        skip 'bidirectional-control filenames are forbidden by the Windows filesystem'
        skip 'printable UTF-8 filename preservation is not exercised on Windows'
        ;;
    *)
        tree=$(fresh_tree control-path)
        control_name=$'escape\033[31m.txt'
        printf '\177ELF\002\001\001\000compiled' >"$tree/$control_name"
        if "$SCANNER" --tree "$tree" >"$TEST_TMP/output" 2>&1; then
            printf 'not ok - control-byte path was not rejected\n'
            exit 1
        elif grep -q $'\033' "$TEST_TMP/output" ||
             ! grep -Fq 'escape\x1b[31m.txt' "$TEST_TMP/output"; then
            printf 'not ok - control-byte path was not rendered safely\n'
            exit 1
        else
            pass 'scanner escapes terminal control bytes in reported paths'
        fi

        tree=$(fresh_tree raw-c1-path)
        control_name=$'raw-\200.txt'
        if { printf '\177ELF\002\001\001\000compiled' >"$tree/$control_name"; } 2>/dev/null; then
            if "$SCANNER" --tree "$tree" >"$TEST_TMP/output" 2>&1; then
                printf 'not ok - raw C1 path was not rejected\n'
                exit 1
            elif ! grep -Fq 'raw-\x80.txt' "$TEST_TMP/output" ||
                 LC_ALL=C grep -q $'\200' "$TEST_TMP/output"; then
                printf 'not ok - raw C1 path was not rendered safely\n'
                exit 1
            else
                pass 'scanner escapes invalid raw C1 bytes in reported paths'
            fi
        else
            skip 'raw C1 filenames are forbidden by this filesystem'
        fi

        tree=$(fresh_tree utf8-c1-path)
        control_name=$'utf8-\302\233.txt'
        printf '\177ELF\002\001\001\000compiled' >"$tree/$control_name"
        if "$SCANNER" --tree "$tree" >"$TEST_TMP/output" 2>&1; then
            printf 'not ok - UTF-8 C1 path was not rejected\n'
            exit 1
        elif ! grep -Fq 'utf8-\u009b.txt' "$TEST_TMP/output" ||
             LC_ALL=C grep -q $'\302\233' "$TEST_TMP/output"; then
            printf 'not ok - UTF-8 C1 path was not rendered safely\n'
            exit 1
        else
            pass 'scanner escapes UTF-8-encoded C1 controls in reported paths'
        fi

        tree=$(fresh_tree bidi-path)
        control_name=$'report-\342\200\256txt.exe'
        printf '\177ELF\002\001\001\000compiled' >"$tree/$control_name"
        if "$SCANNER" --tree "$tree" >"$TEST_TMP/output" 2>&1; then
            printf 'not ok - bidirectional-control path was not rejected\n'
            exit 1
        elif ! grep -Fq 'report-\u202etxt.exe' "$TEST_TMP/output" ||
             LC_ALL=C grep -q $'\342\200\256' "$TEST_TMP/output"; then
            printf 'not ok - bidirectional-control path was not rendered safely\n'
            exit 1
        else
            pass 'scanner escapes UTF-8 bidirectional controls in reported paths'
        fi

        tree=$(fresh_tree printable-utf8-path)
        control_name=$'caf\303\251.txt'
        printf '\177ELF\002\001\001\000compiled' >"$tree/$control_name"
        if "$SCANNER" --tree "$tree" >"$TEST_TMP/output" 2>&1; then
            printf 'not ok - printable UTF-8 path was not rejected\n'
            exit 1
        elif ! LC_ALL=C grep -Fq -- "$control_name" "$TEST_TMP/output"; then
            printf 'not ok - printable UTF-8 path was not preserved\n'
            exit 1
        else
            pass 'scanner preserves printable UTF-8 in reported paths'
        fi
        ;;
esac

tree=$(fresh_tree ar)
printf '!<arch>\n' >"$tree/renamed.data"
expect_fail_tree 'ar library renamed as data is rejected' "$tree" renamed.data

tree=$(fresh_tree thin-ar)
printf '!<thin>\n' >"$tree/renamed.data"
expect_fail_tree 'GNU thin archive renamed as data is rejected' "$tree" renamed.data

tree=$(fresh_tree mz)
printf 'MZnot-source' >"$tree/renamed.data"
expect_fail_tree 'PE/MZ renamed as data is rejected' "$tree" renamed.data

tree=$(fresh_tree macho)
printf '\376\355\372\317compiled' >"$tree/renamed.data"
expect_fail_tree 'Mach-O renamed as data is rejected' "$tree" renamed.data

tree=$(fresh_tree coff)
printf '\144\206\001\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' >"$tree/renamed.data"
expect_fail_tree 'COFF object renamed as data is rejected' "$tree" renamed.data

tree=$(fresh_tree lfs)
printf 'version https://git-lfs.github.com/spec/v1\noid sha256:0000\nsize 4\n' >"$tree/pointer.c"
expect_fail_tree 'unresolved Git LFS pointer is rejected' "$tree" pointer.c

tree=$(fresh_tree symlink)
if ((SYMLINKS_SUPPORTED)) && ln -s ../../outside "$tree/escape" 2>/dev/null &&
        [[ -L $tree/escape ]]; then
    expect_fail_tree 'escaping symlink is rejected' "$tree" escape
else
    skip 'escaping symlink test is unsupported by this runner'
fi

tree=$(fresh_tree so-version)
printf 'not actually compiled\n' >"$tree/libexample.so.1"
expect_fail_tree 'versioned shared-library extension is rejected' "$tree" libexample.so.1

tree=$(fresh_tree rpm)
printf '\355\253\356\333package' >"$tree/renamed.data"
expect_fail_tree 'RPM magic is rejected without relying on extension' "$tree" renamed.data

tree=$(fresh_tree deb)
printf '!<arch>\ndebian-binary   000000000000000000000000000000000000000000000000000000\n' >"$tree/renamed.data"
expect_fail_tree 'DEB magic is rejected without relying on extension' "$tree" renamed.data

tree=$(fresh_tree appimage)
printf '\177ELF\002\001\001\000AI\002payload' >"$tree/renamed.data"
expect_fail_tree 'AppImage magic is rejected without relying on extension' "$tree" renamed.data

tree=$(fresh_tree wasm)
printf '\000asm\001\000\000\000' >"$tree/module.data"
expect_fail_tree 'WebAssembly magic is rejected' "$tree" module.data

tree=$(fresh_tree class)
printf '\312\376\272\276\000\000\000\075' >"$tree/class.data"
expect_fail_tree 'Java class magic is rejected' "$tree" class.data

tree=$(fresh_tree pyc)
printf '\247\015\015\012\000\000\000\000\000\000\000\000\000\000\000\000' >"$tree/python.data"
expect_fail_tree 'Python bytecode magic is rejected' "$tree" python.data

tree=$(fresh_tree nested)
mkdir -p "$tree/input"
printf '\177ELF\002\001\001\000nested' >"$tree/input/payload.txt"
tar -C "$tree/input" -cf "$tree/outer.tar" payload.txt
rm -rf -- "$tree/input"
expect_fail_tree 'compiled content inside an archive is rejected' "$tree" 'outer.tar!payload.txt'

tree=$(fresh_tree renamed-7z)
printf '\067\172\274\257\047\034malformed' >"$tree/renamed.data"
expect_fail_tree '7z magic is recognized and cannot bypass archive inspection' \
    "$tree" renamed.data

tree=$(fresh_tree renamed-rar)
printf 'Rar!\032\007\001\000malformed' >"$tree/renamed.data"
expect_fail_tree 'RAR magic is recognized and cannot bypass archive inspection' \
    "$tree" renamed.data

tree=$(fresh_tree empty-archive)
tar -cf "$tree/empty.tar" --files-from /dev/null
expect_fail_tree 'empty archives are rejected as having no inspectable source' \
    "$tree" empty.tar

tree=$(fresh_tree member-limit)
mkdir -p "$tree/input"
for member_number in 1 2 3 4; do
    printf 'source %s\n' "$member_number" >"$tree/input/$member_number.c"
done
tar -C "$tree/input" -cf "$tree/members.tar" .
expect_fail_archive_with_limits \
    'archive member count is bounded during preflight listing' \
    "$tree/members.tar" 'archive member limit exceeded' \
    SOURCE_AUDIT_MAX_MEMBERS=3

expect_fail_archive_with_limits \
    'archive member-name output is byte-bounded during preflight listing' \
    "$tree/members.tar" 'archive member-name budget exceeded' \
    SOURCE_AUDIT_MAX_LIST_KIB=0

tree=$(fresh_tree expanded-limit)
mkdir -p "$tree/input"
dd if=/dev/zero of="$tree/input/zeros.c" bs=1024 count=2048 2>/dev/null
tar -C "$tree/input" -czf "$tree/compressed-size-bomb.tar.gz" zeros.c
expect_fail_archive_with_limits \
    'compressed archive declared size is rejected before extraction' \
    "$tree/compressed-size-bomb.tar.gz" \
    'archive declared-size limit exceeded before extraction' \
    SOURCE_AUDIT_MAX_KIB=1024

tree=$(fresh_tree global-expanded-limit)
mkdir -p "$tree/one" "$tree/two"
dd if=/dev/zero of="$tree/one/one.c" bs=700 count=1 2>/dev/null
dd if=/dev/zero of="$tree/two/two.c" bs=700 count=1 2>/dev/null
tar -C "$tree/one" -cf "$tree/one.tar" one.c
tar -C "$tree/two" -cf "$tree/two.tar" two.c
if env SOURCE_AUDIT_MAX_KIB=2 SOURCE_AUDIT_MAX_TOTAL_KIB=1 \
    "$SCANNER" --archive "$tree/one.tar" --archive "$tree/two.tar" \
    >"$TEST_TMP/output" 2>&1; then
    printf 'not ok - global archive size budget unexpectedly passed\n'
    exit 1
elif grep -Fq 'global archive declared-size budget exceeded' "$TEST_TMP/output"; then
    pass 'global declared-size budget covers multiple archives'
else
    printf 'not ok - global archive size budget finding missing\n'
    sed -n '1,120p' "$TEST_TMP/output"
    exit 1
fi

tree=$(fresh_tree archive-symlink)
mkdir -p "$tree/input"
if ((SYMLINKS_SUPPORTED)) &&
        ln -s ../../outside "$tree/input/escape" 2>/dev/null &&
        [[ -L $tree/input/escape ]]; then
    tar -C "$tree/input" -cf "$tree/escape.tar" escape
    rm -rf -- "$tree/input"
    expect_fail_tree 'escaping symlink inside an archive is rejected before extraction' "$tree" 'escape.tar!escape'
else
    skip 'archive symlink test is unsupported by this runner'
fi

tree=$(fresh_tree bad-ref)
printf 'SDK_LIB = vendor/vuptsdk/libvuptsdk.so.2\n' >"$tree/Makefile"
expect_fail_tree 'removed vendored library references are rejected' "$tree" Makefile

archive_src=$(fresh_tree standalone-archive)
printf 'source text\n' >"$archive_src/source.c"
tar -C "$archive_src" -cf "$TEST_TMP/source.tar" source.c
if "$SCANNER" --archive "$TEST_TMP/source.tar" >"$TEST_TMP/output" 2>&1 &&
   grep -q '^PASS source-only:' "$TEST_TMP/output"; then
    pass 'standalone source archive passes'
else
    printf 'not ok - standalone source archive passes\n'
    sed -n '1,120p' "$TEST_TMP/output"
    exit 1
fi

if SOURCE_AUDIT_FORCE_WATCHDOG=1 \
   "$SCANNER" --archive "$TEST_TMP/source.tar" >"$TEST_TMP/output" 2>&1 &&
   grep -q '^PASS source-only:' "$TEST_TMP/output"; then
    pass 'portable archive watchdog fallback completes a normal scan'
else
    printf 'not ok - portable archive watchdog fallback\n'
    sed -n '1,120p' "$TEST_TMP/output"
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    if python3 - "$SCANNER" "$TEST_TMP/source.tar" "$TEST_TMP/watchdog-children.log" <<'PY'
import ctypes
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

if sys.platform != "linux":
    sys.exit(77)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
libc.prctl.restype = ctypes.c_int
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    sys.exit(77)

scanner, archive, log = sys.argv[1:]
children = Path(f"/proc/self/task/{os.getpid()}/children")
try:
    with open(log, "wb") as output:
        result = subprocess.run(
            [scanner, "--archive", archive],
            env={**os.environ, "SOURCE_AUDIT_FORCE_WATCHDOG": "1"},
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
    if result.returncode != 0 or "PASS source-only:" not in Path(log).read_text():
        raise AssertionError("portable watchdog archive scan failed")
    adopted = []
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            adopted.extend(int(pid) for pid in children.read_text().split())
            break
        adopted.append(pid)
    if adopted:
        raise AssertionError(f"portable watchdog left {len(adopted)} unwaited children")
finally:
    # The real scanner may fail this regression; do not leak its children.
    cleanup_deadline = time.monotonic() + 5
    try:
        while True:
            # Killing a parent can adopt grandchildren after this inventory.
            for pid in map(int, children.read_text().split()):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if time.monotonic() >= cleanup_deadline:
                raise TimeoutError(
                    "portable watchdog child cleanup exceeded five seconds"
                )
            if pid == 0:
                time.sleep(0.01)
    finally:
        if libc.prctl(36, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot restore child subreaper state")
PY
    then
        pass 'portable archive watchdog leaves no unwaited children'
    else
        status=$?
        if ((status == 77)); then
            skip 'portable watchdog child accounting requires Linux subreaper support'
        else
            printf 'not ok - portable archive watchdog child cleanup\n'
            exit "$status"
        fi
    fi
else
    skip 'portable watchdog child accounting requires Python 3'
fi

repo=$TEST_TMP/repository
mkdir -p "$repo"
git -C "$repo" init -q
git -C "$repo" config user.name 'Source Audit Test'
git -C "$repo" config user.email 'source-audit@example.invalid'
printf 'safe source\n' >"$repo/source.c"
printf '*.o\n' >"$repo/.gitignore"
mkdir -p "$repo/tests" "$repo/scripts" "$repo/packaging/opensuse"
printf 'fixture mentions vendor/vuptsdk/libvuptsdk.so.2\n' >"$repo/tests/test_source_only.sh"
printf '# scanner implementation fixture\n' >"$repo/scripts/check-source-only.sh"
printf '# scanner wrapper fixture\n' >"$repo/packaging/opensuse/source-audit.sh"
git -C "$repo" add source.c .gitignore tests scripts packaging
git -C "$repo" commit -qm 'safe source'
git -C "$repo" tag v1.0.0
if "$SCANNER" --root "$repo" --tag v1.0.0 >"$TEST_TMP/output" 2>&1 &&
   grep -q '^PASS source-only:' "$TEST_TMP/output"; then
    pass 'tracked, working-tree, HEAD archive, and tag archive pass'
else
    printf 'not ok - repository and tag audit pass\n'
    sed -n '1,120p' "$TEST_TMP/output"
    exit 1
fi

printf '\177ELF\002\001\001\000ignored' >"$repo/ignored.o"
if "$SCANNER" --root "$repo" >"$TEST_TMP/output" 2>&1; then
    printf 'not ok - ignored working-tree object is rejected\n'
    exit 1
elif grep -Fq ignored.o "$TEST_TMP/output"; then
    pass 'ignored working-tree object is rejected'
else
    printf 'not ok - ignored object path missing\n'
    exit 1
fi
rm -f -- "$repo/ignored.o"

printf '\177ELF\002\001\001\000indexed' >"$repo/indexed.txt"
git -C "$repo" add indexed.txt
printf 'safe worktree replacement\n' >"$repo/indexed.txt"
if "$SCANNER" --root "$repo" >"$TEST_TMP/output" 2>&1; then
    printf 'not ok - compiled indexed blob is rejected\n'
    exit 1
elif grep -Fq indexed.txt "$TEST_TMP/output"; then
    pass 'Git index content is audited independently of the worktree'
else
    printf 'not ok - indexed path missing\n'
    exit 1
fi

# A producer that fails after yielding plausible records is not a clean scan.
export SOURCE_AUDIT_REAL_FIND SOURCE_AUDIT_REAL_GIT
SOURCE_AUDIT_REAL_FIND=$(command -v find)
SOURCE_AUDIT_REAL_GIT=$(command -v git)
enum_shims=$TEST_TMP/enumeration-tools
mkdir "$enum_shims"
for enum_tool in find git; do
    cp -- "${BASH_SOURCE[0]}" "$enum_shims/$enum_tool"
    chmod 700 "$enum_shims/$enum_tool"
done
ENUM_FAILURES=0
run_enumeration_control() {
    local scope=$1 mode=$2 diagnostic=$3 status=0 expected_status=1
    local output=$TEST_TMP/enumeration-output calls=$TEST_TMP/enumeration-calls
    shift 3
    [[ $mode != pass ]] || expected_status=0
    rm -f -- "$calls"
    env PATH="$enum_shims:$PATH" SOURCE_AUDIT_ENUM_CHILD=1 \
        SOURCE_AUDIT_ENUM_SCOPE="$scope" SOURCE_AUDIT_ENUM_MODE="$mode" \
        SOURCE_AUDIT_ENUM_LOG="$calls" \
        "$SCANNER" "$@" >"$output" 2>&1 || status=$?
    printf 'CASE enumeration %s/%s: scanner status %s\n' "$scope" "$mode" "$status"
    cat -- "$output"
    printf '%s %s\n' "$scope" "$mode" >"$TEST_TMP/expected-enumeration-calls"
    if [[ $status != "$expected_status" ]] ||
       ! cmp -s -- "$calls" "$TEST_TMP/expected-enumeration-calls" ||
       grep -Fq 'ENUMERATION-SETUP-FAIL:' "$output"; then
        printf 'not ok - enumeration %s/%s status or fixture setup\n' "$scope" "$mode"
        ENUM_FAILURES=$((ENUM_FAILURES + 1))
    elif [[ $mode == pass ]]; then
        if grep -q '^PASS source-only:' "$output"; then
            pass "successful $scope enumeration passes through the real tool"
        else
            printf 'not ok - enumeration %s pass-through summary\n' "$scope"
            ENUM_FAILURES=$((ENUM_FAILURES + 1))
        fi
    elif grep -Fq "ENUMERATION-PRODUCER-FAULT: $scope $mode" "$output" &&
         grep -Fq -- "$diagnostic" "$output" &&
         grep -q '^FAIL source-only:' "$output" &&
         ! grep -q '^PASS source-only:' "$output"; then
        pass "failed $scope enumeration rejects $mode producer output"
    else
        printf 'not ok - enumeration %s/%s rejection diagnostic\n' "$scope" "$mode"
        ENUM_FAILURES=$((ENUM_FAILURES + 1))
    fi
}

enum_tree=$(fresh_tree enumeration-failure)
printf 'safe source\n' >"$enum_tree/source.c"
printf '\177ELF\002\001\001\000hidden' >"$enum_tree/hidden.txt"
expect_fail_tree 'enumeration fixture contains a rejected payload' "$enum_tree" hidden.txt
enum_safe=$(fresh_tree enumeration-safe)
printf 'first source\n' >"$enum_safe/source.c"
printf 'second source\n' >"$enum_safe/second.c"
enum_archive=$TEST_TMP/enumeration.tar
tar -C "$enum_safe" -cf "$enum_archive" source.c second.c

for enum_mode in empty partial; do
    run_enumeration_control tree "$enum_mode" 'tree enumeration failed' \
        --tree "$enum_tree"
    run_enumeration_control expanded "$enum_mode" 'archive file enumeration failed' \
        --archive "$enum_archive"
    run_enumeration_control index "$enum_mode" 'Git index enumeration failed' \
        --root "$repo"
done
run_enumeration_control tree pass '' --tree "$enum_safe"
run_enumeration_control expanded pass '' --archive "$enum_archive"
# Replace only this test repository's staged binary with its safe worktree copy.
git -C "$repo" add indexed.txt
run_enumeration_control index pass '' --root "$repo"
if ((ENUM_FAILURES)); then
    printf 'FAIL: enumeration controls: %s failed\n' "$ENUM_FAILURES" >&2
    exit 1
fi

export SOURCE_AUDIT_REAL_WC
SOURCE_AUDIT_REAL_WC=$(command -v wc)
byte_shims=$TEST_TMP/byte-count-tools
mkdir "$byte_shims"
cp -- "${BASH_SOURCE[0]}" "$byte_shims/wc"
chmod 700 "$byte_shims/wc"
byte_tree=$(fresh_tree byte-count-safe)
printf 'source audit accounting control\n' >"$byte_tree/source.c"
byte_archive=$TEST_TMP/byte-count.tar
tar -C "$byte_tree" -cf "$byte_archive" source.c
BYTE_FAILURES=0

run_byte_count_control() {
    local mode=$1 status=0 expected_status=1
    local output=$TEST_TMP/byte-count-output calls=$TEST_TMP/byte-count-calls
    [[ $mode != pass ]] || expected_status=0
    rm -f -- "$calls"
    env PATH="$byte_shims:$PATH" SOURCE_AUDIT_BYTE_CHILD=1 \
        SOURCE_AUDIT_BYTE_MODE="$mode" SOURCE_AUDIT_BYTE_LOG="$calls" \
        "$SCANNER" --archive "$byte_archive" >"$output" 2>&1 || status=$?
    printf 'CASE byte-count %s: scanner status %s\n' "$mode" "$status"
    cat -- "$output"
    printf '%s\n' "$mode" >"$TEST_TMP/expected-byte-count-calls"
    if [[ $status != "$expected_status" ]] ||
       ! cmp -s -- "$calls" "$TEST_TMP/expected-byte-count-calls" ||
       ! grep -Fxq 'BYTE-COUNT-REAL: 32' "$output" ||
       grep -Fq 'BYTE-COUNT-SETUP-FAIL:' "$output"; then
        printf 'not ok - byte-count %s status or fixture setup\n' "$mode"
        BYTE_FAILURES=$((BYTE_FAILURES + 1))
    elif [[ $mode == pass ]]; then
        if grep -q '^PASS source-only:' "$output"; then
            pass 'successful extracted-byte count passes through the real tool'
        else
            printf 'not ok - byte-count pass-through summary\n'
            BYTE_FAILURES=$((BYTE_FAILURES + 1))
        fi
    elif grep -Fxq "BYTE-COUNT-PRODUCER-FAULT: $mode" "$output" &&
         grep -Fq 'archive expanded sizes cannot be accounted safely' "$output" &&
         grep -q '^FAIL source-only:' "$output" &&
         ! grep -q '^PASS source-only:' "$output"; then
        pass "failed extracted-byte count rejects $mode producer output"
    else
        printf 'not ok - byte-count %s rejection diagnostic\n' "$mode"
        BYTE_FAILURES=$((BYTE_FAILURES + 1))
    fi
}

for byte_mode in empty zero complete pass; do
    run_byte_count_control "$byte_mode"
done
if ((BYTE_FAILURES)); then
    printf 'FAIL: extracted-byte controls: %s failed\n' "$BYTE_FAILURES" >&2
    exit 1
fi

printf '1..%d\n' "$PASSED"
