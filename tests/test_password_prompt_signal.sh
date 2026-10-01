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
import contextlib
import fcntl
import pty
import select
import signal
import shlex
import struct
import subprocess
import tempfile
import termios
import time
import sys

binary = sys.argv[1]
prompt_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


def drain(master, transcript):
    while select.select([master], [], [], 0)[0]:
        transcript.extend(os.read(master, 4096))


def wait_output(process, master, transcript, expected):
    deadline = time.monotonic() + 10
    while expected not in transcript and time.monotonic() < deadline:
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            transcript.extend(os.read(master, 4096))
        if process.poll() is not None:
            break
    if expected not in transcript:
        raise SystemExit(f"password prompt was not reached: {expected!r}")


def wait_prompt(process, master, transcript):
    wait_output(process, master, transcript, b"Password:")


def dynamic_elf(path):
    # LD_PRELOAD cannot exercise a statically linked CLI. Do not skip its
    # ordinary PTY tests below: static builds need the same echo restoration.
    with open(path, "rb") as stream:
        header = stream.read(64)
        if header[:4] != b"\x7fELF" or header[4] not in (1, 2):
            raise SystemExit("cannot identify Linux CLI ELF linkage")
        endian = "<" if header[5] == 1 else ">"
        if header[4] == 2:
            offset = struct.unpack_from(endian + "Q", header, 32)[0]
            size, count = struct.unpack_from(endian + "HH", header, 54)
        else:
            offset = struct.unpack_from(endian + "I", header, 28)[0]
            size, count = struct.unpack_from(endian + "HH", header, 42)
        for index in range(count):
            stream.seek(offset + index * size)
            if struct.unpack(endian + "I", stream.read(4))[0] == 3:
                return True
    return False


with tempfile.TemporaryDirectory(prefix="zupt-password-signal-") as work:
    source = os.path.join(work, "input.txt")
    archive = os.path.join(work, "interrupted.zupt")
    with open(source, "w", encoding="utf-8") as stream:
        stream.write("terminal restoration regression\n")

    @contextlib.contextmanager
    def child(shim=None, mode="echo", number=signal.SIGINT, controlling=False):
        master, slave = pty.openpty()
        initial = (termios.tcgetattr(slave), fcntl.fcntl(slave, fcntl.F_GETFL))
        event_read, event_write = os.pipe()
        ack_read, ack_write = os.pipe()
        environment = os.environ.copy()
        inherited = ()
        if shim:
            environment["LD_PRELOAD"] = shim
            environment["ZUPT_TEST_EVENT_FD"] = str(event_write)
            environment["ZUPT_TEST_ACK_FD"] = str(ack_read)
            environment["ZUPT_TEST_MODE"] = mode
            environment["ZUPT_TEST_SIGNAL"] = str(number)
            inherited = (event_write, ack_read)
        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        process = subprocess.Popen(
            [binary, "compress", "--password-prompt", archive, source],
            stdin=slave, stdout=slave, stderr=slave, env=environment,
            close_fds=True, pass_fds=inherited,
            cwd=work, preexec_fn=controlling_terminal if controlling else None,
        )
        os.close(event_write)
        os.close(ack_read)
        try:
            yield process, master, slave, initial, event_read, ack_write
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            for descriptor in (master, slave, event_read, ack_write):
                os.close(descriptor)

    def assert_interrupted(process, slave, initial, number):
        name = signal.Signals(number).name
        try:
            status = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise SystemExit(f"password prompt hung after {name}")
        if status != -number:
            raise SystemExit(f"password prompt did not re-raise {name}: {status}")
        restored = termios.tcgetattr(slave)
        if restored != initial[0]:
            raise SystemExit(f"terminal state was not restored after {name}")
        if fcntl.fcntl(slave, fcntl.F_GETFL) != initial[1]:
            raise SystemExit(f"terminal descriptor flags were not restored after {name}")
        if not (restored[3] & termios.ECHO):
            raise SystemExit("terminal echo is disabled after interrupted prompt")
        if os.path.exists(archive):
            raise SystemExit("interrupted password prompt left an archive")

    shim = None
    if sys.platform != "linux":
        print("SKIP: deterministic LD_PRELOAD prompt ordering/interruption tests need Linux")
    elif not dynamic_elf(binary):
        print("SKIP: deterministic LD_PRELOAD prompt ordering/interruption tests need a dynamic CLI")
    else:
        shim_source = os.path.join(work, "prompt_shim.c")
        shim = os.path.join(work, "prompt_shim.so")
        with open(shim_source, "w", encoding="utf-8") as stream:
            stream.write(r'''
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

static int testing(const char *mode) {
    const char *selected = getenv("ZUPT_TEST_MODE");
    return selected && strcmp(selected, mode) == 0;
}

static void handshake(char byte) {
    const char *event = getenv("ZUPT_TEST_EVENT_FD");
    const char *ack = getenv("ZUPT_TEST_ACK_FD");
    if (!event || !ack) _exit(121);
    ssize_t result;
    do { result = write(atoi(event), &byte, 1); }
    while (result < 0 && errno == EINTR);
    if (result != 1) _exit(122);
    do { result = read(atoi(ack), &byte, 1); }
    while (result < 0 && errno == EINTR);
    if (result != 1) _exit(123);
}

int tcsetattr(int fd, int action, const struct termios *attributes) {
    static int (*real_tcsetattr)(int, int, const struct termios *);
    static int paused;
    if (!real_tcsetattr) real_tcsetattr = dlsym(RTLD_NEXT, "tcsetattr");
    if (!real_tcsetattr) _exit(120);
    if (testing("echo") && !paused && fd == STDIN_FILENO &&
        !(attributes->c_lflag & ECHO)) {
        paused = 1;
        handshake('E');
    }
    return real_tcsetattr(fd, action, attributes);
}

char *fgets(char *buffer, int capacity, FILE *stream) {
    static char *(*real_fgets)(char *, int, FILE *);
    static int paused;
    if (!real_fgets) real_fgets = dlsym(RTLD_NEXT, "fgets");
    if (!real_fgets) _exit(124);
    if (testing("read") && !paused && stream == stdin) {
        paused = 1;
        handshake('R');
        /* Deliver synchronously after the caller's signal-flag check but
         * before libc starts its blocking read. No scheduler timing needed. */
        if (raise(atoi(getenv("ZUPT_TEST_SIGNAL"))) != 0) _exit(125);
    }
    return real_fgets(buffer, capacity, stream);
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
            const struct timespec *timeout, const sigset_t *mask) {
    static int (*real_pselect)(int, fd_set *, fd_set *, fd_set *,
                              const struct timespec *, const sigset_t *);
    static int paused;
    if (!real_pselect) real_pselect = dlsym(RTLD_NEXT, "pselect");
    if (!real_pselect) _exit(126);
    if (testing("read") && !paused && readfds && FD_ISSET(STDIN_FILENO, readfds)) {
        paused = 1;
        handshake('R');
        if (raise(atoi(getenv("ZUPT_TEST_SIGNAL"))) != 0) _exit(125);
    }
    return real_pselect(nfds, readfds, writefds, exceptfds, timeout, mask);
}

ssize_t read(int fd, void *buffer, size_t capacity) {
    static ssize_t (*real_read)(int, void *, size_t);
    static int paused;
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    if (!real_read) _exit(127);
    if (testing("flush") && !paused && fd == STDIN_FILENO) {
        paused = 1;
        handshake('F');
    }
    return real_read(fd, buffer, capacity);
}
''')
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                       ["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                        shim_source, "-o", shim, "-ldl"], check=True)
        with child(shim) as (process, master, slave, initial, event, ack):
            if not select.select([event], [], [], 10)[0] or os.read(event, 1) != b"E":
                raise SystemExit("echo-disable interposer handshake was not reached")
            transcript = bytearray()
            drain(master, transcript)
            if b"Password:" in transcript:
                raise SystemExit("password prompt was displayed before echo was disabled")
            if not (termios.tcgetattr(slave)[3] & termios.ECHO):
                raise SystemExit("echo-disable handshake did not pause before the transition")
            os.write(ack, b"A")
            wait_prompt(process, master, transcript)
            if termios.tcgetattr(slave)[3] & termios.ECHO:
                raise SystemExit("terminal echo was not disabled during prompt")
            process.send_signal(signal.SIGINT)
            assert_interrupted(process, slave, initial, signal.SIGINT)
        print("password prompt echo-disable ordering: PASS")

        for number in prompt_signals:
            with child(shim, "read", number) as (process, master, slave, initial, event, ack):
                if not select.select([event], [], [], 10)[0] or os.read(event, 1) != b"R":
                    raise SystemExit("blocking-input interposer handshake was not reached")
                transcript = bytearray()
                wait_prompt(process, master, transcript)
                os.write(ack, b"A")
                assert_interrupted(process, slave, initial, number)
            print(f"password prompt {signal.Signals(number).name} input-entry interruption: PASS")

        for number, control in ((signal.SIGINT, termios.VINTR),
                                (signal.SIGQUIT, termios.VQUIT)):
            with child(shim, "flush", number, controlling=True) as (process, master, slave, initial, event, ack):
                transcript = bytearray()
                wait_prompt(process, master, transcript)
                os.write(master, b"queued-input\n")
                if not select.select([event], [], [], 10)[0] or os.read(event, 1) != b"F":
                    raise SystemExit("ready-input read handshake was not reached")
                os.write(master, initial[0][6][control])
                # Wait for the actual terminal signal to be pending. Its input
                # flush has then happened; elapsed time is not the handshake.
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    with open(f"/proc/{process.pid}/status", encoding="utf-8") as stream:
                        pending = [int(line.split()[1], 16) for line in stream
                                   if line.startswith(("SigPnd:", "ShdPnd:"))]
                    if any(mask & (1 << (number - 1)) for mask in pending):
                        break
                    select.select([], [], [], 0.01)
                else:
                    raise SystemExit("terminal input signal did not become pending")
                os.write(ack, b"A")
                assert_interrupted(process, slave, initial, number)
            print(f"password prompt {signal.Signals(number).name} terminal input-flush interruption: PASS")

    # These are the original real PTY guard, extended to every handled signal.
    # They run even when LD_PRELOAD is unavailable (including musl static CLIs).
    for number in prompt_signals:
        with child() as (process, master, slave, initial, event, ack):
            transcript = bytearray()
            wait_prompt(process, master, transcript)
            if termios.tcgetattr(slave)[3] & termios.ECHO:
                raise SystemExit("terminal echo was not disabled during prompt")
            process.send_signal(number)
            assert_interrupted(process, slave, initial, number)
        print(f"password prompt {signal.Signals(number).name} restoration: PASS")

    for password, prequeue in ((b"Prompt-Roundtrip-2026!", False),
                              (b"B" * 250, False), (b"C" * 255, True)):
        archive = os.path.join(work, f"roundtrip-{len(password)}.zupt")
        with child() as (process, master, slave, initial, event, ack):
            transcript = bytearray()
            wait_prompt(process, master, transcript)
            os.write(master, (password + b"\n") * (2 if prequeue else 1))
            wait_output(process, master, transcript, b"Confirm:")
            if not prequeue:
                if termios.tcgetattr(slave)[3] & termios.ECHO:
                    raise SystemExit("terminal echo was not disabled during confirmation")
                os.write(master, password + b"\n")
            if process.wait(timeout=30) != 0:
                raise SystemExit("interactive password compression failed")
            drain(master, transcript)
            if password in transcript:
                raise SystemExit("interactive password was echoed to the terminal")
            if termios.tcgetattr(slave) != initial[0]:
                raise SystemExit("terminal state was not restored after successful prompts")
            if fcntl.fcntl(slave, fcntl.F_GETFL) != initial[1]:
                raise SystemExit("terminal descriptor flags were not restored after successful prompts")
            password_file = os.path.join(work, "roundtrip-password")
            with open(password_file, "wb") as stream:
                stream.write(password + b"\n")
            result = subprocess.run([binary, "test", "--pass-file", password_file, archive],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if result.returncode != 0:
                raise SystemExit("interactive archive password validation failed")
        print(f"password prompt {len(password)}-byte hidden input and confirmation: PASS")

    for length in (0, 256):
        archive = os.path.join(work, f"rejected-{length}.zupt")
        with child() as (process, master, slave, initial, event, ack):
            transcript = bytearray()
            wait_prompt(process, master, transcript)
            os.write(master, b"D" * length + b"\n")
            if process.wait(timeout=10) != 1 or os.path.exists(archive):
                raise SystemExit(f"{length}-byte interactive password was not rejected")
            if termios.tcgetattr(slave) != initial[0]:
                raise SystemExit("terminal state was not restored after rejected input")
            if fcntl.fcntl(slave, fcntl.F_GETFL) != initial[1]:
                raise SystemExit("terminal descriptor flags were not restored after rejected input")
        print(f"password prompt {length}-byte input rejection: PASS")
PY
