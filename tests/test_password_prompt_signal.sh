#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# A signal received while a password is read must not leave terminal echo off.

set -Eeuo pipefail

bin=${1:-./zupt}
if [[ ! -x $bin ]]; then
    printf 'FAIL: ZUPT binary is not executable: %s\n' "$bin" >&2
    exit 1
fi
case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*)
        printf '%s\n' \
            'SKIP: POSIX pseudo-terminal signal restoration test is unavailable on Windows'
        exit 0
        ;;
esac
if ! command -v python3 >/dev/null 2>&1; then
    printf 'SKIP: password-prompt signal test needs python3 with pty support\n'
    exit 0
fi

bin=$(cd "$(dirname "$bin")" && pwd -P)/$(basename "$bin")
python3 - "$bin" <<'PY'
import os
import pty
import select
import signal
import subprocess
import tempfile
import termios
import time
import sys

binary = sys.argv[1]
with tempfile.TemporaryDirectory(prefix="zupt-password-signal-") as work:
    source = os.path.join(work, "input.txt")
    archive = os.path.join(work, "interrupted.zupt")
    with open(source, "w", encoding="utf-8") as stream:
        stream.write("terminal restoration regression\n")

    master, slave = pty.openpty()
    initial = termios.tcgetattr(slave)
    process = subprocess.Popen(
        [binary, "compress", "--password-prompt", archive, source],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    transcript = bytearray()
    deadline = time.monotonic() + 10
    try:
        while b"Password:" not in transcript and time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                transcript.extend(os.read(master, 4096))
            if process.poll() is not None:
                break
        if b"Password:" not in transcript:
            raise SystemExit("password prompt was not reached")
        hidden = termios.tcgetattr(slave)
        if hidden[3] & termios.ECHO:
            raise SystemExit("terminal echo was not disabled during prompt")

        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
        restored = termios.tcgetattr(slave)
        if (restored[3] & termios.ECHO) != (initial[3] & termios.ECHO):
            raise SystemExit("terminal echo state was not restored after SIGINT")
        if not (restored[3] & termios.ECHO):
            raise SystemExit("terminal echo is disabled after interrupted prompt")
        if os.path.exists(archive):
            raise SystemExit("interrupted password prompt left an archive")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)

print("password prompt signal restoration: PASS")
PY
