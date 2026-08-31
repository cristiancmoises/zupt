#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

binary=${1:-./zupt}
case $binary in
    /*) ;;
    *) binary=$PWD/${binary#./} ;;
esac

test_root=$(mktemp -d "${TMPDIR:-/tmp}/zupt-password.XXXXXXXX")
cleanup() {
    chmod -R u+rwX "$test_root" 2>/dev/null || true
    rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

cd "$test_root"
printf 'password source round-trip\n' > 'entrada ação.txt'
printf 'Correct-Horse-Battery-Staple-2026!\n' > 'senha segura.txt'
chmod 600 'senha segura.txt'

"$binary" compress --pass-file 'senha segura.txt' archive.zupt \
    'entrada ação.txt' >/dev/null 2>&1
"$binary" test --pass-file 'senha segura.txt' archive.zupt >/dev/null 2>&1
mkdir extracted
"$binary" extract --pass-file 'senha segura.txt' -o extracted \
    archive.zupt >/dev/null 2>&1
cmp 'entrada ação.txt' 'extracted/entrada ação.txt'

case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*)
        printf '%s\n' 'SKIP: inherited POSIX descriptor mapping is not portable in MSYS'
        ;;
    *)
        exec 9<'senha segura.txt'
        "$binary" test --pass-fd 9 archive.zupt >/dev/null 2>&1
        exec 9<&-
        ;;
esac

printf '\n' > empty-password
if "$binary" test --pass-file empty-password archive.zupt >/dev/null 2>&1; then
    printf '%s\n' 'FAIL: accepted an empty password file' >&2
    exit 1
fi

printf 'bad\0password\n' > nul-password
if "$binary" test --pass-file nul-password archive.zupt >/dev/null 2>&1; then
    printf '%s\n' 'FAIL: accepted a password file containing NUL' >&2
    exit 1
fi

if "$binary" test --pass-fd not-a-number archive.zupt >/dev/null 2>&1; then
    printf '%s\n' 'FAIL: accepted an invalid password descriptor' >&2
    exit 1
fi

if "$binary" test --password-prompt archive.zupt </dev/null >/dev/null 2>&1; then
    printf '%s\n' 'FAIL: non-interactive password prompt unexpectedly succeeded' >&2
    exit 1
fi

case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*)
        printf '%s\n' 'SKIP: POSIX pseudo-terminal password overflow test is unavailable in MSYS'
        ;;
    *)
        if command -v python3 >/dev/null 2>&1; then
            python3 - "$binary" "$test_root" <<'PY'
import errno
import os
import pty
import select
import sys
import time

binary, root = sys.argv[1:]
archive = os.path.join(root, "prompt-overflow.zupt")
source = os.path.join(root, "entrada ação.txt")
pid, descriptor = pty.fork()
if pid == 0:
    os.execv(binary, [binary, "compress", "--password-prompt", archive, source])

deadline = time.monotonic() + 20
output = bytearray()
sent = False
status = None
while time.monotonic() < deadline:
    ready, _, _ = select.select([descriptor], [], [], 0.1)
    if ready:
        try:
            chunk = os.read(descriptor, 4096)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            chunk = b""
        output.extend(chunk)
        if not sent and b"Password:" in output:
            os.write(descriptor, b"A" * 510 + b"\n")
            sent = True
    waited, status = os.waitpid(pid, os.WNOHANG)
    if waited == pid:
        break
else:
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    raise SystemExit("password overflow prompt timed out")

success = status is not None and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
if not sent or success:
    raise SystemExit("overlong interactive password was accepted")
if os.path.exists(archive):
    raise SystemExit("overlong interactive password published an archive")
PY
        else
            printf '%s\n' 'SKIP: python3 is unavailable for pseudo-terminal password overflow test'
        fi
        ;;
esac

if "$binary" test -p incorrect archive.zupt >/dev/null 2>&1; then
    printf '%s\n' 'FAIL: incorrect password unexpectedly succeeded' >&2
    exit 1
fi

if "$binary" --version | grep -q 'libvuptsdk=disabled'; then
    if "$binary" compress -p secret --kdf argon2id downgrade.zupt \
        'entrada ação.txt' >/dev/null 2>&1; then
        printf '%s\n' 'FAIL: source-only build silently accepted unavailable Argon2id' >&2
        exit 1
    fi
fi

printf '%s\n' 'PASS: password prompt/file/fd validation and encrypted round-trip'
