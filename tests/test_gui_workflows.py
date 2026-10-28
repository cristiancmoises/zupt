#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

"""Exercise the Qt worker and archive actions against the selected CLI."""

import importlib.machinery
import importlib.util
import io
import os
import re
import runpy
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

COMPLETE = "PASS: GUI_WORKFLOWS_COMPLETE"
# A GUI close failure can call os._exit(0). Require normal test completion,
# not merely exit status zero, and bound a stuck Qt event loop externally.
if __name__ == "__main__" and "--run-tests" not in sys.argv:
    process = subprocess.Popen(
        [sys.executable, __file__, "--run-tests", *sys.argv[1:]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=os.name == "posix",
    )
    try:
        out, err = process.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        out, err = process.communicate()
        sys.stdout.write(out)
        sys.stderr.write(err)
        raise SystemExit("FAIL: GUI workflow test process timed out")
    sys.stdout.write(out)
    sys.stderr.write(err)
    if process.returncode or COMPLETE not in out.splitlines():
        raise SystemExit("FAIL: GUI workflow tests did not complete successfully")
    raise SystemExit(0)


ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("ZUPT_BIN", ROOT / "zupt")).resolve()
if not CLI.is_file() or not os.access(CLI, os.X_OK):
    raise RuntimeError("Build the CLI first or set ZUPT_BIN to a tested executable")
os.environ["ZUPT_BIN"] = str(CLI)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
MODULE = Path(os.environ.get("ZUPT_GUI_MODULE", ROOT / "gui/src/zupt_gui.py")).resolve()
SPEC = importlib.util.spec_from_file_location("zupt_gui", MODULE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load the selected GUI module")
GUI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUI)
if Path(GUI.ZUPT_CLI).resolve() != CLI:
    raise RuntimeError("GUI discovery did not select the requested CLI")
VERSION_MATCH = re.search(
    r'^#define ZUPT_VERSION_STRING "([^"]+)"',
    (ROOT / "include/zupt.h").read_text(),
    re.MULTILINE,
)
if VERSION_MATCH is None:
    raise RuntimeError("Cannot find ZUPT_VERSION_STRING in include/zupt.h")
VERSION = VERSION_MATCH.group(1)
if GUI.ZUPT_VER_NUMBER != VERSION:
    raise RuntimeError("The selected CLI does not match the source version")

if TYPE_CHECKING or GUI.QT_BINDING == "PySide6":
    from PySide6.QtCore import Slot
else:
    from PyQt6.QtCore import pyqtSlot as Slot


class DeletionObserver(GUI.QObject):
    """Keep a GUI-thread receiver alive beyond the objects being observed."""

    def __init__(self, parent):
        super().__init__(parent)
        self.calls = []
        self.callback_threads = []

    @Slot()
    def record(self):
        self.calls.append(True)
        self.callback_threads.append(GUI.QThread.currentThread())


class BootstrapGuardTests(unittest.TestCase):
    def assert_bootstrap_rejected(self, message):
        with patch.dict(os.environ), self.assertRaises(RuntimeError) as rejected:
            runpy.run_path(__file__, run_name="gui_bootstrap_guard")
        self.assertEqual(str(rejected.exception), message)

    def test_missing_spec_is_rejected_before_module_creation(self):
        with (
            patch.object(importlib.util, "spec_from_file_location", return_value=None),
            patch.object(importlib.util, "module_from_spec") as create,
        ):
            self.assert_bootstrap_rejected("Cannot load the selected GUI module")
            create.assert_not_called()

    def test_missing_loader_is_rejected_before_module_creation(self):
        spec = importlib.machinery.ModuleSpec("zupt_gui", None)
        with (
            patch.object(importlib.util, "spec_from_file_location", return_value=spec),
            patch.object(importlib.util, "module_from_spec") as create,
        ):
            self.assert_bootstrap_rejected("Cannot load the selected GUI module")
            create.assert_not_called()

    def test_missing_source_version_is_rejected_after_the_header_read(self):
        header = ROOT / "include/zupt.h"
        reads = []
        original_read_text = Path.read_text

        def read_header(path, *args, **kwargs):
            if path == header:
                reads.append(path)
                return "/* Fixture deliberately lacks the version macro. */\n"
            return original_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", read_header):
            self.assert_bootstrap_rejected(
                "Cannot find ZUPT_VERSION_STRING in include/zupt.h"
            )
        self.assertEqual(reads, [header])


class CapabilityLabelTests(unittest.TestCase):
    def test_sdk_labels_describe_the_public_provider_boundary(self):
        with patch.object(GUI, "SDK_AVAILABLE", True):
            label = next(
                label for label, token in GUI.pq_mode_options() if token == "sdk"
            )
        self.assertIn("system libvuptsdk", label)

        detected_labels = []
        for spelling in ("SDK v2", "SDK-v2"):
            with (
                self.subTest(spelling=spelling),
                patch.object(
                    GUI,
                    "_archive_info_text",
                    return_value=(
                        f"Encrypted: YES\nPost-quantum: libvuptsdk {spelling} "
                        "recipient envelope\n"
                    ),
                ),
            ):
                self.assertEqual(GUI._detect_archive_pq("fixture.zupt"), "sdk")
                kind, detected_label = GUI._detect_archive_enc("fixture.zupt")
                self.assertEqual(kind, "sdk")
                self.assertIn("recipient envelope", detected_label)
                detected_labels.append(detected_label)

        descriptions = "\n".join((label, *detected_labels)).lower()
        for provider_detail in ("hkdf", "commitment", "hpke"):
            self.assertNotIn(provider_detail, descriptions)


@unittest.skipUnless(os.name == "posix", "CLI probe fixtures require POSIX shebangs")
class CliProbeTests(unittest.TestCase):
    def setUp(self):
        interpreter = os.fsencode(sys.executable)
        if (
            any(character in interpreter for character in (9, 10, 13, 32))
            or len(interpreter) > 125
        ):
            self.skipTest("selected Python path cannot be used in a portable shebang")
        self.temp = tempfile.TemporaryDirectory(prefix="zupt-gui-probe-")
        self.addCleanup(self.temp.cleanup)
        self.probe = Path(self.temp.name) / "probe cli"
        self.marker = Path(self.temp.name) / "help-called"
        selected_cli = patch.object(GUI, "ZUPT_CLI", str(self.probe))
        selected_cli.start()
        self.addCleanup(selected_cli.stop)

    def write_cli(self, args, status=0, stdout="", stderr="", mark_call=False):
        marker = (
            "from pathlib import Path\n"
            f"Path({str(self.marker)!r}).write_text('called', encoding='utf-8')\n"
            if mark_call
            else ""
        )
        self.probe.write_text(
            f"#!{sys.executable}\nimport sys\n"
            + marker
            + f"if sys.argv[1:] != {args!r}:\n    raise SystemExit(93)\n"
            + f"sys.stdout.write({stdout!r})\n"
            + f"sys.stderr.write({stderr!r})\n"
            + f"raise SystemExit({status})\n",
            encoding="utf-8",
        )
        self.probe.chmod(0o700)

    def test_runnable_classifies_exit_status_and_first_diagnostic(self):
        self.assertEqual(GUI._is_runnable(self.probe), (False, "not a regular file"))
        self.write_cli(["version"])
        self.probe.chmod(0o600)
        self.assertEqual(
            GUI._is_runnable(self.probe), (False, "not executable (chmod +x needed?)")
        )
        for status, stderr, expected in (
            (0, "ignored warning\n", (True, "OK")),
            (
                7,
                "first diagnostic\nsecond diagnostic\n",
                (False, "exit 7: first diagnostic"),
            ),
            (7, "", (False, "exit 7: no stderr")),
        ):
            with self.subTest(status=status, stderr=stderr):
                self.write_cli(["version"], status=status, stderr=stderr)
                self.assertEqual(GUI._is_runnable(self.probe), expected)

    def test_version_only_accepts_successful_banners(self):
        for status, output, expected in (
            (
                0,
                " \nzupt 9.8.7\nbuild details\n ",
                ("zupt 9.8.7", "9.8.7", "zupt 9.8.7\nbuild details"),
            ),
            (0, "vaptvupt 9.8.7\n", ("vaptvupt 9.8.7", "9.8.7", "vaptvupt 9.8.7")),
            (7, "zupt 9.8.7\nbuild details\n", ("zupt (not found)", "?", "")),
        ):
            with self.subTest(status=status, output=output):
                self.write_cli(["version"], status=status, stdout=output)
                self.assertEqual(GUI._get_version(), expected)

    def test_capabilities_fall_back_to_help_output_on_both_exit_statuses(self):
        enabled = (
            "Build integrations: libvuptsdk=enabled libpqvaptvupt=enabled\n"
            "KDF: Argon2id (default)\n"
        )
        for banner, expected in (
            ("", (False, False, True, "PBKDF2-SHA256")),
            (enabled, (True, True, True, "Argon2id")),
        ):
            for status in (0, 7):
                for stream in ("stdout", "stderr"):
                    with self.subTest(banner=banner, status=status, stream=stream):
                        output = {"stdout": "", "stderr": ""}
                        output[stream] = "usage: --pq-only\n"
                        self.write_cli(
                            ["help"],
                            status=status,
                            stdout=output["stdout"],
                            stderr=output["stderr"],
                        )
                        with patch.object(GUI, "ZUPT_VER_FULL", banner):
                            self.assertEqual(GUI._get_caps(), expected)
        self.write_cli(["help"], status=7, stderr="ordinary help\n")
        with patch.object(GUI, "ZUPT_VER_FULL", ""):
            self.assertEqual(GUI._get_caps(), (False, False, False, "PBKDF2-SHA256"))

    def test_cached_capabilities_do_not_spawn_help(self):
        self.write_cli(["help"], status=7, stderr="ordinary help\n", mark_call=True)
        banner = (
            "Build integrations: libvuptsdk=enabled libpqvaptvupt=enabled\n"
            "KDF: Argon2id (default)\n--pq-only\n"
        )
        with patch.object(GUI, "ZUPT_VER_FULL", banner):
            self.assertEqual(GUI._get_caps(), (True, True, True, "Argon2id"))
        self.assertFalse(
            self.marker.exists(), "cached capabilities launched the help probe"
        )

    def test_archive_info_preserves_both_streams_after_nonzero_exit(self):
        for status in (0, 7):
            with self.subTest(status=status):
                self.write_cli(
                    ["info", "archive with spaces.zupt"],
                    status=status,
                    stdout="archive detail\n",
                    stderr="info warning\n",
                )
                self.assertEqual(
                    GUI._archive_info_text("archive with spaces.zupt"),
                    "archive detail\ninfo warning\n",
                )

    def test_run_zupt_preserves_status_streams_and_arguments(self):
        for status in (0, 7):
            with self.subTest(status=status):
                args = ["probe", "argument with spaces", "--literal"]
                self.write_cli(
                    args,
                    status=status,
                    stdout="command output\n",
                    stderr="command warning\n",
                )
                self.assertEqual(
                    GUI.run_zupt(args),
                    (status, "command output\n", "command warning\n"),
                )
                self.assertEqual(args, ["probe", "argument with spaces", "--literal"])


class CliQueryFailureTests(unittest.TestCase):
    def test_expected_query_failures_preserve_fallbacks_without_output(self):
        banner = (
            "Build integrations: libvuptsdk=enabled libpqvaptvupt=enabled\n"
            "KDF: Argon2id (default)\n"
        )
        queries = (
            ("version", GUI._get_version, ("zupt (not found)", "?", "")),
            ("help", GUI._get_caps, (True, True, False, "Argon2id")),
            ("info", lambda: GUI._archive_info_text("fixture.zupt"), ""),
        )
        failures = (
            OSError("fixture process detail"),
            FileNotFoundError("fixture process detail"),
            PermissionError("fixture process detail"),
            subprocess.SubprocessError("fixture process detail"),
            subprocess.TimeoutExpired(["fixture", "private argument"], 5),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "fixture process detail"),
        )
        with patch.object(GUI, "ZUPT_VER_FULL", banner):
            for name, query, expected in queries:
                for failure in failures:
                    with (
                        self.subTest(query=name, failure=type(failure).__name__),
                        patch.object(GUI.subprocess, "run", side_effect=failure) as run,
                        patch.object(sys, "stdout", new_callable=io.StringIO) as out,
                        patch.object(sys, "stderr", new_callable=io.StringIO) as err,
                    ):
                        self.assertEqual(query(), expected)
                        run.assert_called_once()
                        self.assertEqual(out.getvalue(), "")
                        self.assertEqual(err.getvalue(), "")

    def test_unexpected_query_errors_are_not_reported_as_missing_metadata(self):
        queries = (
            ("version", GUI._get_version),
            ("help", GUI._get_caps),
            ("info", lambda: GUI._archive_info_text("fixture.zupt")),
        )
        with patch.object(GUI, "ZUPT_VER_FULL", ""):
            for name, query in queries:
                for kind in (TypeError, AttributeError, RuntimeError):
                    failure = kind("fixture programming error")
                    with (
                        self.subTest(query=name, failure=kind.__name__),
                        patch.object(GUI.subprocess, "run", side_effect=failure) as run,
                    ):
                        with self.assertRaises(kind) as raised:
                            query()
                        self.assertIs(raised.exception, failure)
                        run.assert_called_once()


class WorkerLogTests(unittest.TestCase):
    def assert_chunked_output(
        self, chunks, expected_lines, expected_percentages=(), worker=None
    ):
        if worker is None:
            worker = GUI.Worker(["version"])
        child = subprocess.Popen(
            [sys.executable, "-c", "pass"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        connections = []
        try:
            output = child.stdout
            if output is None:
                self.fail("fixture child has no output pipe")
            logs, percentages, done, states = [], [], [], []

            def completed(*result):
                done.append(result)
                states.append((child.returncode, output.closed))

            for signal, callback in (
                (worker.log, logs.append),
                (worker.pct, percentages.append),
                (worker.done, completed),
            ):
                signal.connect(callback)
                connections.append((signal, callback))
            # OS writes can coalesce. Fix only the read boundaries while the
            # real Worker still owns, reaps, and closes a real child's pipe.
            with (
                patch.object(output, "read1", side_effect=[*chunks, b""]),
                patch.object(GUI.subprocess, "Popen", return_value=child),
            ):
                worker.run()
            self.assertEqual(logs, [f"$ {CLI.name} version", *expected_lines])
            self.assertEqual(percentages, list(expected_percentages))
            self.assertEqual(done, [(0, "", "\n".join(expected_lines))])
            self.assertEqual(states, [(0, True)], "done preceded child cleanup")
            if os.name == "posix":
                with self.assertRaises(ChildProcessError):
                    os.waitpid(child.pid, os.WNOHANG)
        finally:
            try:
                for signal, callback in connections:
                    signal.disconnect(callback)
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                if child.stdout is not None:
                    child.stdout.close()

    def test_utf8_characters_survive_every_chunk_boundary_and_bytewise_reads(self):
        fixtures = (
            (b"\xc3\xa9", "é"),
            (b"\xe6\xbc\xa2", "漢"),
            (b"\xf0\x9f\x99\x82", "🙂"),
        )
        for encoded, character in fixtures:
            boundaries = [
                (str(split), [encoded[:split], encoded[split:]])
                for split in range(1, len(encoded))
            ]
            boundaries.append(("bytewise", [bytes([byte]) for byte in encoded]))
            for boundary, parts in boundaries:
                for ending in (b"\n", b""):
                    with self.subTest(
                        character=character, boundary=boundary, ending=ending
                    ):
                        self.assert_chunked_output(
                            [b"before ", *parts, b" after" + ending],
                            [f"before {character} after"],
                        )

    def test_split_utf8_logs_keep_interleaved_progress_and_the_eof_tail(self):
        self.assert_chunked_output(
            [
                b"caf\xc3",
                b"\xa9\n\r input [#] 10%\r",
                b"\xe6",
                b"\xbc",
                b"\xa2\n\r input [##] 42%\r",
                b"tail \xf0\x9f",
                b"\x99\x82",
            ],
            ["café", "漢", "tail 🙂"],
            [10, 42],
        )

    def test_malformed_and_incomplete_utf8_keep_the_replacement_policy(self):
        fixtures = (
            ([b"bad \xff bytes\n"], ["bad � bytes"]),
            ([b"bad \xe2", b"(\xa1\n"], ["bad �(�"]),
            ([b"tail \xc3"], ["tail �"]),
            ([b"tail \xe2", b"\x82"], ["tail �"]),
            ([b"tail \xf0", b"\x9f"], ["tail �"]),
            ([b"bad \xf0\x9f", b"\nnext\n"], ["bad �", "next"]),
        )
        for chunks, expected_lines in fixtures:
            with self.subTest(chunks=chunks):
                self.assert_chunked_output(chunks, expected_lines)

    def test_empty_chunk_is_eof_without_an_extra_log_or_completion(self):
        fixtures = (
            ([], []),
            ([b"", b"unread\n"], []),
            ([b"tail", b"", b"unread\n"], ["tail"]),
        )
        for chunks, expected_lines in fixtures:
            with self.subTest(chunks=chunks):
                self.assert_chunked_output(chunks, expected_lines)

    def test_reusing_a_worker_does_not_carry_incomplete_utf8_into_the_next_run(self):
        worker = GUI.Worker(["version"])
        self.assert_chunked_output([b"first \xf0", b"\x9f"], ["first �"], worker=worker)
        self.assert_chunked_output([b"\x99\x82\n"], ["��"], worker=worker)
        self.assert_chunked_output(
            [b"fresh \xc3", b"\xa9\n"], ["fresh é"], worker=worker
        )

    def run_cleanup_worker(self, child, args=None, on_done=None):
        worker = GUI.Worker(args if args is not None else ["version"])
        done, states, logs = [], [], []
        worker.log.connect(logs.append)

        def completed(*result):
            done.append(result)
            # poll() would reap a real child and hide a missing Worker wait.
            states.append((child.returncode, child.stdout.closed))
            if on_done is not None:
                on_done()

        worker.done.connect(completed)
        with patch.object(GUI.subprocess, "Popen", return_value=child):
            worker.run()
        return done, states, logs

    def test_read_failure_reaps_a_live_child_before_completion(self):
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys, time; print('ready', flush=True); time.sleep(60)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        try:
            output = child.stdout
            if output is None:
                self.fail("fixture child has no output pipe")
            self.assertEqual(output.readline(), b"ready\n")
            self.assertIsNone(child.returncode)
            with patch.object(
                output, "read1", side_effect=OSError("fixture read failure")
            ):
                done, states, _ = self.run_cleanup_worker(child)
            self.assertEqual(done, [(-1, "", "OSError: fixture read failure")])
            self.assertEqual(len(states), 1)
            self.assertIsNotNone(states[0][0], "done preceded child reaping")
            self.assertTrue(states[0][1], "done preceded pipe closure")
            if os.name == "posix":
                with self.assertRaises(ChildProcessError):
                    os.waitpid(child.pid, os.WNOHANG)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            if child.stdout is not None:
                child.stdout.close()

    def test_wait_timeout_kills_and_reaps_before_completion(self):
        child = Mock()
        child.stdout = io.BytesIO()
        child.returncode = None
        child.poll.return_value = None

        def waited(timeout):
            if child.wait.call_count == 1:
                raise subprocess.TimeoutExpired(["fixture"], timeout)
            child.returncode = -9
            return child.returncode

        child.wait.side_effect = waited
        done, states, _ = self.run_cleanup_worker(child)
        self.assertEqual(done, [(-1, "", "Timed out")])
        self.assertEqual(states, [(-9, True)])
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.call_count, 2)
        first_timeout = child.wait.call_args_list[0].kwargs["timeout"]
        self.assertGreater(first_timeout, 0)
        self.assertLessEqual(first_timeout, 7200)
        self.assertEqual(child.wait.call_args_list[1], call(timeout=5))

    def test_exit_race_still_waits_and_closes_before_completion(self):
        child = Mock()
        child.stdout = io.BytesIO()
        child.stdout.read1 = Mock(side_effect=OSError("fixture read failure"))
        child.returncode = None
        child.poll.return_value = None
        child.kill.side_effect = ProcessLookupError("fixture exited")

        def waited(timeout):
            child.returncode = 0
            return 0

        child.wait.side_effect = waited
        done, states, _ = self.run_cleanup_worker(child)
        self.assertEqual(done, [(-1, "", "OSError: fixture read failure")])
        self.assertEqual(states, [(0, True)])
        child.kill.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=5)

    def test_kill_failure_does_not_skip_wait_or_pipe_closure(self):
        child = Mock()
        child.stdout = io.BytesIO()
        child.stdout.read1 = Mock(side_effect=OSError("fixture read failure"))
        child.returncode = None
        child.poll.return_value = None
        secret = "fake-cleanup-secret-817"
        child.kill.side_effect = PermissionError(secret)
        child.wait.side_effect = subprocess.TimeoutExpired(["fixture", "-p", secret], 5)
        done, states, logs = self.run_cleanup_worker(child, ["test", "-p", secret])
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0][0], -1)
        self.assertIn("OSError: fixture read failure", done[0][2])
        self.assertIn("terminate: PermissionError", done[0][2])
        self.assertIn("wait: TimeoutExpired", done[0][2])
        self.assertEqual(states, [(None, True)])
        child.wait.assert_called_once_with(timeout=5)
        self.assertNotIn(secret, "\n".join(logs) + done[0][2])

    def test_poll_or_wait_failure_still_closes_and_reports_once(self):
        for stage in ("poll", "wait"):
            with self.subTest(stage=stage):
                child = Mock()
                child.stdout = io.BytesIO()
                child.stdout.read1 = Mock(side_effect=OSError("fixture read failure"))
                child.returncode = None
                child.poll.return_value = 0
                getattr(child, stage).side_effect = OSError("private fixture detail")
                done, states, logs = self.run_cleanup_worker(child)
                self.assertEqual(len(done), 1)
                self.assertEqual(done[0][0], -1)
                self.assertIn("OSError: fixture read failure", done[0][2])
                self.assertIn(
                    f"{'terminate' if stage == 'poll' else 'wait'}: OSError", done[0][2]
                )
                self.assertEqual(states, [(None, True)])
                child.wait.assert_called_once_with(timeout=5)
                self.assertNotIn("private fixture detail", "\n".join(logs) + done[0][2])

    def test_pipe_close_failure_turns_success_into_one_failure(self):
        child = Mock()
        child.stdout = io.BytesIO()
        child.returncode = 0
        child.poll.return_value = 0
        try:
            with patch.object(
                child.stdout, "close", side_effect=OSError("private fixture detail")
            ):
                done, states, logs = self.run_cleanup_worker(child)
            self.assertEqual(len(done), 1)
            self.assertEqual(done[0][0], -1)
            self.assertIn("close: OSError", done[0][2])
            self.assertEqual(states, [(0, False)])
            self.assertNotIn("private fixture detail", "\n".join(logs) + done[0][2])
        finally:
            child.stdout.close()

    def test_worker_closes_child_output_after_success_or_read_failure(self):
        for read_failure in (False, True):
            with self.subTest(read_failure=read_failure):
                child = Mock()
                child.stdout = io.BytesIO(b"fixture output\n")
                child.returncode = 0
                if read_failure:
                    child.stdout.read1 = Mock(
                        side_effect=OSError("fixture read failure")
                    )
                child.poll.return_value = 0
                done, states, _ = self.run_cleanup_worker(child)
                self.assertEqual(len(done), 1)
                self.assertEqual(done[0][0], -1 if read_failure else 0)
                self.assertTrue(
                    child.stdout.closed, "Worker leaked its child output pipe"
                )
                self.assertEqual(states, [(0, True)])

    def test_missing_cli_still_completes_without_an_output_pipe(self):
        done = []
        worker = GUI.Worker(["version"])
        worker.done.connect(lambda *result: done.append(result))
        with patch.object(GUI.subprocess, "Popen", side_effect=FileNotFoundError):
            worker.run()
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0][0], -1)

    def run_worker(self, args):
        child = Mock()
        child.stdout = io.BytesIO()
        child.returncode = 0
        worker = GUI.Worker(args)
        lines, done = [], []
        worker.log.connect(lines.append)
        worker.done.connect(lambda *result: done.append(result))
        with patch.object(GUI.subprocess, "Popen", return_value=child) as spawn:
            worker.run()
        spawn.assert_called_once_with(
            [str(CLI)] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        self.assertEqual(done, [(0, "", "")])
        self.assertEqual(worker.args, args)
        self.assertEqual(len(lines), 1)
        return lines[0]

    def test_password_values_are_redacted_without_changing_child_arguments(self):
        for flag in ("-p", "--password"):
            for password in (
                "fixture-secret-817",
                "fake password with spaces",
                "fake\npassword\tvalue",
                "fictícia-密碼-817",
            ):
                with self.subTest(flag=flag, password_kind=len(password)):
                    args = ["compress", "--vv", flag, password, "backup.zupt", "input"]
                    original = args.copy()
                    line = self.run_worker(args)
                    self.assertNotIn(password, line)
                    self.assertIn(flag + " [redacted]", line)
                    self.assertEqual(args, original)

    def test_multiple_password_options_do_not_leave_a_value_in_the_log(self):
        line = self.run_worker(
            ["test", "-p", "fake-one-817", "--password", "fake-two-818", "backup.zupt"]
        )
        self.assertNotIn("fake-one-817", line)
        self.assertNotIn("fake-two-818", line)
        self.assertEqual(line.count("[redacted]"), 2)

    def test_empty_and_option_like_values_are_redacted_conservatively(self):
        for password in ("", "--password", "-p", "-fake-value"):
            with self.subTest(value=password):
                line = self.run_worker(["test", "-p", password, "backup.zupt"])
                self.assertEqual(line, f"$ {CLI.name} test -p [redacted] backup.zupt")

    def test_non_password_options_and_missing_value_keep_their_display(self):
        for args in (
            ["test", "--pass-file", "private-file", "backup.zupt"],
            ["extract", "--pass-fd", "3", "backup.zupt"],
            ["test", "--password-prompt", "backup.zupt"],
            ["test", "-p"],
        ):
            with self.subTest(args=args):
                self.assertEqual(
                    self.run_worker(args), f"$ {CLI.name} {' '.join(args)}"
                )

    def deadline_child(self, body):
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import os, sys, time; print('ready', flush=True); " + body,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )

        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            if child.stdout is not None:
                child.stdout.close()

        self.addCleanup(cleanup)
        output = child.stdout
        if output is None:
            self.fail("fixture child has no output pipe")
        self.assertEqual(output.readline(), b"ready\n")
        return child

    def test_missing_output_pipe_reaps_before_single_completion(self):
        child = self.deadline_child("time.sleep(3)")
        worker = GUI.Worker(["version"])
        done, states = [], []
        worker.done.connect(lambda *result: done.append(result))
        worker.done.connect(lambda *_: states.append(child.returncode))
        with (
            patch.object(child, "stdout", None),
            patch.object(GUI.subprocess, "Popen", return_value=child),
        ):
            worker.run()
        self.assertEqual(done, [(-1, "", "RuntimeError: CLI output pipe unavailable")])
        self.assertEqual(len(states), 1)
        self.assertIsNotNone(states[0], "done preceded child reaping")
        self.assertNotEqual(states[0], 0)
        if os.name == "posix":
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)

    def test_missing_or_noncallable_reader_cleans_up_before_single_completion(self):
        for reader in (None, False):
            with self.subTest(reader=reader):
                child = self.deadline_child("time.sleep(3)")
                output = io.StringIO()
                self.addCleanup(output.close)
                worker = GUI.Worker(["version"])
                done, states = [], []
                worker.done.connect(lambda *result, done=done: done.append(result))
                worker.done.connect(
                    lambda *_, states=states, child=child, output=output: states.append(
                        (child.returncode, output.closed)
                    )
                )
                with (
                    patch.object(output, "read1", reader, create=True),
                    patch.object(child, "stdout", output),
                    patch.object(GUI.subprocess, "Popen", return_value=child),
                ):
                    worker.run()
                self.assertEqual(
                    done, [(-1, "", "TypeError: CLI output reader unavailable")]
                )
                self.assertEqual(len(states), 1)
                self.assertIsNotNone(states[0][0], "done preceded child reaping")
                self.assertNotEqual(states[0][0], 0)
                self.assertTrue(states[0][1], "done preceded pipe closure")
                if os.name == "posix":
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(child.pid, os.WNOHANG)

    def test_nonbytes_reader_return_cleans_up_before_single_completion(self):
        for returned in ("", None, bytearray(b"fixture output\n")):
            with self.subTest(returned=returned):
                child = self.deadline_child("time.sleep(3)")
                output = io.BytesIO()
                self.addCleanup(output.close)
                worker = GUI.Worker(["version"])
                done, states = [], []
                worker.done.connect(lambda *result, done=done: done.append(result))
                worker.done.connect(
                    lambda *_, states=states, child=child, output=output: states.append(
                        (child.returncode, output.closed)
                    )
                )
                with (
                    patch.object(output, "read1", side_effect=[returned, b""]),
                    patch.object(child, "stdout", output),
                    patch.object(GUI.subprocess, "Popen", return_value=child),
                ):
                    worker.run()
                self.assertEqual(
                    done, [(-1, "", "TypeError: CLI output reader returned non-bytes")]
                )
                self.assertEqual(len(states), 1)
                self.assertIsNotNone(states[0][0], "done preceded child reaping")
                self.assertNotEqual(states[0][0], 0)
                self.assertTrue(states[0][1], "done preceded pipe closure")
                if os.name == "posix":
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(child.pid, os.WNOHANG)

    def test_deadline_interrupts_a_silent_child_and_live_progress(self):
        for progress in (False, True):
            with self.subTest(progress=progress):
                body = "time.sleep(3)"
                if progress:
                    body = (
                        "print('\\r input [###] 42%\\r', end='', flush=True); " + body
                    )
                child = self.deadline_child(body)
                output = child.stdout
                if output is None:
                    self.fail("fixture child has no output pipe")
                worker = GUI.Worker(["version"])
                done, states, percentages = [], [], []
                worker.done.connect(lambda *result, done=done: done.append(result))
                worker.done.connect(
                    lambda *_, states=states, child=child, output=output: states.append(
                        (child.returncode, output.closed)
                    )
                )
                worker.pct.connect(
                    lambda value, percentages=percentages, child=child: (
                        percentages.append((value, child.returncode))
                    )
                )
                with (
                    patch.object(GUI.subprocess, "Popen", return_value=child),
                    patch.object(GUI.Worker, "_TIMEOUT_SECONDS", 0.2, create=True),
                ):
                    started = time.monotonic()
                    worker.run()
                    elapsed = time.monotonic() - started
                self.assertEqual(done, [(-1, "", "Timed out")])
                self.assertLess(elapsed, 2, "timeout merely labeled a natural exit")
                self.assertEqual(len(states), 1)
                self.assertIsNotNone(states[0][0], "done preceded child reaping")
                self.assertNotEqual(states[0][0], 0, "child was not interrupted")
                self.assertTrue(states[0][1], "done preceded pipe closure")
                self.assertEqual(percentages, [(42, None)] if progress else [])
                if os.name == "posix":
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(child.pid, os.WNOHANG)

    def test_deadline_also_bounds_wait_after_output_eof(self):
        child = self.deadline_child("os.close(1); os.close(2); time.sleep(3)")
        with patch.object(GUI.Worker, "_TIMEOUT_SECONDS", 0.2, create=True):
            done, states, _ = self.run_cleanup_worker(child)
        self.assertEqual(done, [(-1, "", "Timed out")])
        self.assertIsNotNone(states[0][0])
        self.assertNotEqual(states[0][0], 0)
        self.assertTrue(states[0][1])

    def test_output_read_time_is_deducted_from_the_wait_budget(self):
        child = Mock()
        child.stdout = io.BytesIO()
        child.returncode = 0
        child.poll.return_value = 0
        with patch.object(time, "monotonic", side_effect=[100, 101, 110]):
            self.run_cleanup_worker(child)
        self.assertEqual(
            child.wait.call_args_list, [call(timeout=7190), call(timeout=5)]
        )

    def test_spawn_time_is_deducted_from_the_wait_budget(self):
        child = Mock()
        child.stdout = io.BytesIO()
        child.returncode = 0
        child.poll.return_value = 0
        clock, done = [100], []
        worker = GUI.Worker(["version"])
        worker.done.connect(lambda *result: done.append(result))

        def spawn(*args, **kwargs):
            clock[0] = 7100
            return child

        with (
            patch.object(time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(GUI.subprocess, "Popen", side_effect=spawn),
        ):
            worker.run()
        self.assertEqual(done, [(0, "", "")])
        self.assertEqual(
            child.wait.call_args_list, [call(timeout=200), call(timeout=5)]
        )

    def test_cancel_before_wait_timeout_preserves_cancellation_result(self):
        child = Mock()
        child.stdout = io.BytesIO()
        child.returncode = None
        child.poll.return_value = None
        worker = GUI.Worker(["version"])
        done, states = [], []
        worker.done.connect(lambda *result: done.append(result))
        worker.done.connect(
            lambda *_: states.append((child.returncode, child.stdout.closed))
        )

        def read(count):
            worker.cancel()
            return b""

        def waited(timeout):
            if child.wait.call_count == 1:
                raise subprocess.TimeoutExpired(["fixture"], timeout)
            child.returncode = -9
            return -9

        child.stdout.read1 = Mock(side_effect=read)
        child.wait.side_effect = waited
        with patch.object(GUI.subprocess, "Popen", return_value=child):
            worker.run()
        self.assertEqual(done, [(-1, "", "")])
        self.assertEqual(states, [(-9, True)])
        self.assertEqual(child.wait.call_count, 2)
        self.assertEqual(child.wait.call_args_list[1], call(timeout=5))

    def test_cancel_after_committed_deadline_does_not_hide_timeout(self):
        child = self.deadline_child("time.sleep(3)")
        output = child.stdout
        if output is None:
            self.fail("fixture child has no output pipe")
        worker = GUI.Worker(["version"])
        original_kill = child.kill
        cancelled, done = [], []

        def killed():
            # The deadline is committed before the callback tries to kill.
            if not cancelled:
                cancelled.append(True)
                worker.cancel()
            original_kill()

        worker.done.connect(lambda *result: done.append(result))
        with (
            patch.object(GUI.subprocess, "Popen", return_value=child),
            patch.object(child, "kill", side_effect=killed),
            patch.object(GUI.Worker, "_TIMEOUT_SECONDS", 0.05, create=True),
        ):
            worker.run()
        self.assertEqual(cancelled, [True])
        self.assertEqual(done, [(-1, "", "Timed out")])
        self.assertNotEqual(child.returncode, 0)
        self.assertTrue(output.closed)

    def test_production_deadline_timer_is_joined_before_success(self):
        child = self.deadline_child("print('finished', flush=True)")
        real_timer, timers, at_done = threading.Timer, [], []

        def timer_for(interval, callback):
            timer = real_timer(interval, callback)
            timers.append(timer)
            return timer

        with (
            patch.object(threading, "Timer", side_effect=timer_for),
            patch.object(time, "monotonic", return_value=100),
        ):
            done, states, _ = self.run_cleanup_worker(
                child, on_done=lambda: at_done.append([t.is_alive() for t in timers])
            )
        self.assertEqual(done, [(0, "", "finished")])
        self.assertEqual(states, [(0, True)])
        self.assertEqual(len(timers), 1)
        self.assertEqual(timers[0].interval, 7200)
        self.assertTrue(timers[0].daemon)
        self.assertEqual(at_done, [[False]])

    def test_child_thread_pressure_cannot_prevent_watchdog_start(self):
        real_timer, real_spawn = threading.Timer, subprocess.Popen
        timers, children, done, states = [], [], [], []
        child_launched = False
        worker = GUI.Worker(["version"])

        def timer_for(interval, callback):
            timer = real_timer(interval, callback)
            original_start = timer.start

            def start():
                if child_launched:
                    raise RuntimeError("fixture child exhausted thread budget")
                original_start()

            timer.start = start
            timers.append(timer)
            return timer

        def spawn(*args, **kwargs):
            nonlocal child_launched
            child_launched = True
            child = real_spawn(
                [sys.executable, "-c", "print('child completed')"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
            children.append(child)
            return child

        worker.done.connect(lambda *result: done.append(result))
        worker.done.connect(
            lambda *_: states.append(
                (
                    children[0].returncode,
                    children[0].stdout.closed,
                    [timer.is_alive() for timer in timers],
                )
            )
        )
        try:
            with (
                patch.object(threading, "Timer", side_effect=timer_for),
                patch.object(GUI.subprocess, "Popen", side_effect=spawn),
            ):
                worker.run()
            self.assertEqual(done, [(0, "", "child completed")])
            self.assertEqual(states, [(0, True, [False])])
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                child.stdout.close()

    def test_deadline_fired_during_spawn_interrupts_the_child_after_launch(self):
        real_timer, real_spawn = threading.Timer, subprocess.Popen
        entered = threading.Event()
        timers, children, done, states, fired_during_spawn = [], [], [], [], []
        worker = GUI.Worker(["version"])

        def timer_for(interval, callback):
            def expire():
                entered.set()
                callback()

            timer = real_timer(interval, expire)
            timers.append(timer)
            return timer

        def spawn(*args, **kwargs):
            fired_during_spawn.append(entered.wait(1))
            child = real_spawn(
                [sys.executable, "-c", "import time; time.sleep(3)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
            children.append(child)
            return child

        worker.done.connect(lambda *result: done.append(result))
        worker.done.connect(
            lambda *_: states.append(
                (
                    children[0].returncode,
                    children[0].stdout.closed,
                    [timer.is_alive() for timer in timers],
                )
            )
        )
        try:
            with (
                patch.object(threading, "Timer", side_effect=timer_for),
                patch.object(GUI.subprocess, "Popen", side_effect=spawn),
                patch.object(GUI.Worker, "_TIMEOUT_SECONDS", 0.05),
            ):
                worker.run()
            self.assertEqual(fired_during_spawn, [True])
            self.assertEqual(done, [(-1, "", "Timed out")])
            self.assertNotEqual(states[0][0], 0)
            self.assertIsNotNone(states[0][0])
            self.assertEqual(states[0][1:], (True, [False]))
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                child.stdout.close()

    def test_spawn_failure_releases_a_watchdog_already_in_its_callback(self):
        real_timer = threading.Timer
        for error in (FileNotFoundError, OSError):
            with self.subTest(error=error.__name__):
                entered = threading.Event()
                timers, done, at_done, uncaught, fired_during_spawn = [], [], [], [], []
                worker = GUI.Worker(["version"])

                def timer_for(interval, callback, entered=entered, timers=timers):
                    def expire():
                        entered.set()
                        callback()

                    timer = real_timer(interval, expire)
                    timers.append(timer)
                    return timer

                def spawn(
                    *args,
                    entered=entered,
                    error=error,
                    fired_during_spawn=fired_during_spawn,
                    **kwargs,
                ):
                    fired_during_spawn.append(entered.wait(1))
                    raise error("fixture spawn failed")

                worker.done.connect(lambda *result, done=done: done.append(result))
                worker.done.connect(
                    lambda *_, at_done=at_done, timers=timers: at_done.append(
                        [timer.is_alive() for timer in timers]
                    )
                )
                with (
                    patch.object(threading, "Timer", side_effect=timer_for),
                    patch.object(GUI.subprocess, "Popen", side_effect=spawn),
                    patch.object(threading, "excepthook", side_effect=uncaught.append),
                    patch.object(GUI.Worker, "_TIMEOUT_SECONDS", 0.05),
                ):
                    worker.run()
                self.assertEqual(fired_during_spawn, [True])
                self.assertEqual(len(done), 1)
                self.assertEqual(done[0][0], -1)
                self.assertNotIn("Timed out", done[0][2])
                self.assertIsNone(worker.proc)
                self.assertEqual(at_done, [[False]])
                self.assertEqual(uncaught, [])

    def test_cancellation_during_spawn_does_not_commit_a_timeout(self):
        real_timer, real_spawn = threading.Timer, subprocess.Popen
        entered = threading.Event()
        timers, children, done, states, fired_during_spawn = [], [], [], [], []
        worker = GUI.Worker(["version"])

        def timer_for(interval, callback):
            def expire():
                entered.set()
                callback()

            timer = real_timer(interval, expire)
            timers.append(timer)
            return timer

        def spawn(*args, **kwargs):
            fired_during_spawn.append(entered.wait(1))
            worker.cancel()
            child = real_spawn(
                [sys.executable, "-c", "import time; time.sleep(3)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
            children.append(child)
            return child

        worker.done.connect(lambda *result: done.append(result))
        worker.done.connect(
            lambda *_: states.append(
                (
                    children[0].returncode,
                    children[0].stdout.closed,
                    [timer.is_alive() for timer in timers],
                )
            )
        )
        try:
            with (
                patch.object(threading, "Timer", side_effect=timer_for),
                patch.object(GUI.subprocess, "Popen", side_effect=spawn),
                patch.object(GUI.Worker, "_TIMEOUT_SECONDS", 0.05),
            ):
                worker.run()
            self.assertEqual(fired_during_spawn, [True])
            self.assertEqual(len(done), 1)
            self.assertNotEqual(done[0][0], 0)
            self.assertEqual(done[0][2], "")
            self.assertIsNotNone(states[0][0])
            self.assertNotEqual(states[0][0], 0)
            self.assertEqual(states[0][1:], (True, [False]))
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                child.stdout.close()

    def test_timer_creation_or_start_failure_does_not_launch_a_child(self):
        real_timer = threading.Timer
        secret = "fake-deadline-secret-817"
        for stage in ("construct", "start"):
            with self.subTest(stage=stage):
                timers, done, logs = [], [], []
                worker = GUI.Worker(["test", "-p", secret])
                worker.done.connect(lambda *result, done=done: done.append(result))
                worker.log.connect(logs.append)

                def timer_for(interval, callback, *, stage=stage, timers=timers):
                    if stage == "construct":
                        raise RuntimeError(secret)
                    timer = real_timer(interval, callback)
                    timer.start = Mock(side_effect=RuntimeError(secret))
                    timers.append(timer)
                    return timer

                with (
                    patch.object(threading, "Timer", side_effect=timer_for),
                    patch.object(
                        GUI.subprocess,
                        "Popen",
                        side_effect=AssertionError(
                            "child launched before watchdog reservation"
                        ),
                    ) as spawn,
                ):
                    worker.run()
                self.assertEqual(len(done), 1)
                self.assertEqual(done[0][0], -1)
                self.assertIn("deadline start: RuntimeError", done[0][2])
                self.assertNotIn(secret, "\n".join(logs) + done[0][2])
                spawn.assert_not_called()
                self.assertIsNone(worker.proc)
                self.assertFalse(any(t.is_alive() for t in timers))

    def test_deadline_callback_failures_are_reported_without_secret_details(self):
        secret = "fake-callback-secret-817"
        for stage in ("poll", "kill"):
            with self.subTest(stage=stage):
                child = self.deadline_child("time.sleep(0.4)")
                uncaught = []
                original = getattr(child, stage)

                def failed(*args, original=original, **kwargs):
                    if isinstance(threading.current_thread(), threading.Timer):
                        raise PermissionError(secret)
                    return original(*args, **kwargs)

                with (
                    patch.object(child, stage, side_effect=failed),
                    patch.object(threading, "excepthook", side_effect=uncaught.append),
                    patch.object(GUI.Worker, "_TIMEOUT_SECONDS", 0.05, create=True),
                ):
                    done, states, logs = self.run_cleanup_worker(
                        child, ["test", "-p", secret]
                    )
                self.assertEqual(len(done), 1)
                self.assertEqual(done[0][0], -1)
                self.assertIn(
                    f"deadline {'terminate' if stage == 'kill' else 'poll'}: PermissionError",
                    done[0][2],
                )
                self.assertNotIn(secret, "\n".join(logs) + done[0][2])
                self.assertEqual(uncaught, [])
                self.assertEqual(states, [(0, True)])

    def test_running_deadline_callback_finishes_before_done_on_exit_or_cancel(self):
        real_timer = threading.Timer
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                child = self.deadline_child("time.sleep(0.4)")
                output = child.stdout
                if output is None:
                    self.fail("fixture child has no output pipe")
                worker = GUI.Worker(["version"])
                entered, release, joining = (threading.Event() for _ in range(3))
                timers, done, states, control_errors = [], [], [], []
                original_poll = child.poll

                def polled(
                    *,
                    original_poll=original_poll,
                    timers=timers,
                    entered=entered,
                    release=release,
                ):
                    result = original_poll()
                    if threading.current_thread() in timers:
                        entered.set()
                        if not release.wait(3):
                            raise RuntimeError("fixture callback release timed out")
                    return result

                def timer_for(interval, callback, *, joining=joining, timers=timers):
                    timer = real_timer(interval, callback)
                    original_join = timer.join

                    def timer_join(*args, **kwargs):
                        joining.set()
                        original_join(*args, **kwargs)

                    timer.join = timer_join
                    timers.append(timer)
                    return timer

                def control(
                    *,
                    entered=entered,
                    control_errors=control_errors,
                    cancel=cancel,
                    worker=worker,
                    joining=joining,
                    release=release,
                ):
                    try:
                        if not entered.wait(3):
                            control_errors.append("deadline callback did not start")
                        elif cancel:
                            worker.cancel()
                        elif not joining.wait(3):
                            control_errors.append(
                                "worker did not join the running timer"
                            )
                    finally:
                        release.set()

                worker.done.connect(lambda *result, done=done: done.append(result))
                worker.done.connect(
                    lambda *_, states=states, child=child, output=output, timers=timers: (
                        states.append(
                            (
                                child.returncode,
                                output.closed,
                                [t.is_alive() for t in timers],
                            )
                        )
                    )
                )
                controller = threading.Thread(target=control, daemon=True)
                with (
                    patch.object(GUI.subprocess, "Popen", return_value=child),
                    patch.object(child, "poll", side_effect=polled),
                    patch.object(threading, "Timer", side_effect=timer_for),
                    patch.object(GUI.Worker, "_TIMEOUT_SECONDS", 0.05, create=True),
                ):
                    controller.start()
                    try:
                        worker.run()
                    finally:
                        release.set()
                        controller.join(timeout=4)
                self.assertFalse(controller.is_alive())
                self.assertEqual(control_errors, [])
                self.assertEqual(len(done), 1)
                self.assertNotEqual(done[0][0], 0)
                self.assertEqual(done[0][2], "" if cancel else "Timed out")
                self.assertIsNotNone(states[0][0])
                self.assertEqual(states[0][1:], (True, [False]))


class LogRenderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = GUI.QApplication.instance() or GUI.QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.log = GUI.Log()

    def tearDown(self):
        self.log.close()
        self.log.deleteLater()
        self.app.sendPostedEvents(None, GUI.QEvent.Type.DeferredDelete)
        self.app.processEvents()

    def test_markup_is_literal_and_keeps_the_plain_character_format(self):
        initial_format = self.log.currentCharFormat()
        text = "<b>forged PASS</b><br><i>archive entry</i>"
        self.log.append(text)
        self.assertEqual(self.log.toPlainText(), text)
        cursor = self.log.document().find("forged PASS")
        self.assertFalse(cursor.isNull())
        self.assertEqual(cursor.charFormat().fontWeight(), initial_format.fontWeight())
        self.assertEqual(cursor.charFormat().fontItalic(), initial_format.fontItalic())
        self.assertFalse(cursor.charFormat().isAnchor())

    def test_entities_and_unicode_remain_exactly_as_received(self):
        text = "<p>ação &amp; &lt;密碼&gt; &#65; &#x1F512; 🔒</p>"
        self.log.append(text)
        self.assertEqual(self.log.toPlainText(), text)

    def test_repeated_appends_keep_literal_output_in_order(self):
        initial_format = self.log.currentCharFormat()
        self.log.append("$ zupt test backup.zupt")
        self.log.append("<b>forged PASS</b>")
        self.log.append("ERROR: checksum mismatch")
        self.assertEqual(
            self.log.toPlainText(),
            "$ zupt test backup.zupt\n<b>forged PASS</b>\nERROR: checksum mismatch",
        )
        last_format = self.log.document().lastBlock().begin().fragment().charFormat()
        self.assertEqual(last_format.fontWeight(), initial_format.fontWeight())
        self.assertEqual(last_format.fontItalic(), initial_format.fontItalic())

    def test_multiline_and_empty_appends_preserve_line_boundaries(self):
        cases = (
            (("",), ""),
            (("", "first"), "first"),
            (("first", "", "second"), "first\n\nsecond"),
            (("first\n\nsecond\n", "last"), "first\n\nsecond\n\nlast"),
            (("first\n<b>entry</b>\n\nlast",), "first\n<b>entry</b>\n\nlast"),
        )
        for entries, expected in cases:
            with self.subTest(entries=entries):
                self.log.clear()
                for entry in entries:
                    self.log.append(entry)
                self.assertEqual(self.log.toPlainText(), expected)

    def test_read_only_height_and_plain_log_output_are_preserved(self):
        self.assertTrue(self.log.isReadOnly())
        self.assertEqual(self.log.maximumHeight(), 150)
        custom = GUI.Log(87)
        try:
            self.assertTrue(custom.isReadOnly())
            self.assertEqual(custom.maximumHeight(), 87)
        finally:
            custom.deleteLater()
        self.log.append("$ zupt test backup.zupt")
        self.log.append("Checksum: OK")
        self.assertEqual(
            self.log.toPlainText(), "$ zupt test backup.zupt\nChecksum: OK"
        )

    def test_log_keeps_the_existing_stylesheet(self):
        self.log.setStyleSheet(GUI.STYLE)
        self.log.show()
        self.log.ensurePolished()
        self.app.processEvents()
        palette = self.log.palette()
        roles = GUI.QPalette.ColorRole
        self.assertEqual(palette.color(roles.Base).name(), "#060c10")
        self.assertEqual(palette.color(roles.Text).name(), "#608898")
        self.assertEqual(self.log.font().pixelSize(), 11)

    def test_appending_preserves_the_users_text_selection(self):
        self.log.append("first line\nselected archive entry\nlast line")
        cursor = self.log.document().find("selected archive entry")
        self.assertFalse(cursor.isNull())
        self.log.setTextCursor(cursor)
        anchor, position = cursor.anchor(), cursor.position()
        self.log.append("new CLI output")
        cursor = self.log.textCursor()
        self.assertEqual(cursor.selectedText(), "selected archive entry")
        self.assertEqual((cursor.anchor(), cursor.position()), (anchor, position))

    def test_appending_follows_the_bottom_but_preserves_a_scrolled_up_view(self):
        self.log.resize(320, 96)
        self.log.show()
        for index in range(80):
            self.log.append(f"archive entry {index:03d}")
        self.app.processEvents()
        scrollbar = self.log.verticalScrollBar()
        self.assertGreater(scrollbar.maximum(), 0)
        scrollbar.setValue(scrollbar.maximum())
        self.log.append("output while following the bottom")
        self.app.processEvents()
        self.assertEqual(scrollbar.value(), scrollbar.maximum())
        scrollbar.setValue(0)
        self.app.processEvents()
        self.log.append("output while reading older entries")
        self.app.processEvents()
        self.assertEqual(scrollbar.value(), 0)


class GuiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = GUI.QApplication.instance() or GUI.QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)
        print(
            f"GUI binding: {GUI.QT_BINDING}; module: {MODULE}; CLI: {CLI}", flush=True
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zupt-gui-workflow-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input with spaces"
        self.input.mkdir()
        self.files = {
            "alpha.txt": b"independent frames and archive checks\n" * 1024,
            "bytes.bin": bytes(range(256)) * 129,
            "empty": b"",
        }
        for name, data in self.files.items():
            (self.input / name).write_bytes(data)
        self.archive = self.root / "backup.zupt"
        self.password = "Gui-fixture-only-817! with spaces"
        self.window = GUI.ZuptWindow()
        self.window.show()
        self.app.processEvents()
        self.compress = self.window.compress_tab
        self.extract = self.window.extract_tab
        self.verify = self.window.tabs.widget(3)
        self.thread_errors = []
        self.dialogs = []
        self.observed_methods = []

        def unexpected_dialog(parent, title, text, *args):
            self.dialogs.append(text)
            return GUI.QMessageBox.StandardButton.Cancel

        dialog_patch = patch.object(
            GUI.QMessageBox, "warning", side_effect=unexpected_dialog
        )
        dialog_patch.start()
        self.addCleanup(dialog_patch.stop)
        # Observe existing callbacks without changing their signal connections.
        # Do not perform a Qt write if a callback arrives on the worker thread.
        for tab, button, log, progress in (
            (
                self.compress,
                self.compress.btn,
                self.compress.log,
                self.compress.progress,
            ),
            (self.extract, self.extract.btn, self.extract.log, self.extract.progress),
            (self.verify, self.verify.vbtn, self.verify.vlog, self.verify.vprogress),
        ):
            for widget, methods in (
                (button, ("setEnabled",)),
                (log, ("append",)),
                (progress, ("setRange", "setValue", "show", "hide")),
            ):
                for name in methods:
                    method = getattr(widget, name)

                    def observed(*args, method=method, name=name):
                        if GUI.QThread.currentThread() != self.app.thread():
                            self.thread_errors.append(name)
                            return
                        return method(*args)

                    setattr(widget, name, observed)
                    self.observed_methods.append((widget, name))

    def tearDown(self):
        failed_joins = []
        for i in range(self.window.tabs.count()):
            tab = self.window.tabs.widget(i)
            for job in list(getattr(tab, "_jobs", [])):
                if not job.cancel_and_join(3000):
                    failed_joins.append(job)
        if failed_joins:
            print("FAIL: worker teardown timed out", file=sys.stderr, flush=True)
            os._exit(1)  # Do not destroy live QThreads or continue into another case.
        try:
            self.wait_until(
                lambda: all(
                    not getattr(self.window.tabs.widget(i), "_jobs", [])
                    for i in range(self.window.tabs.count())
                ),
                timeout=3,
            )
        except AssertionError:
            print("FAIL: GUI job cleanup did not complete", file=sys.stderr, flush=True)
            os._exit(1)
        self.window.close()
        for widget, name in self.observed_methods:
            delattr(widget, name)
        self.observed_methods.clear()
        self.window.deleteLater()
        self.app.sendPostedEvents(None, GUI.QEvent.Type.DeferredDelete)
        self.app.processEvents()
        self.assertEqual(self.thread_errors, [], "Widget callbacks left the GUI thread")
        self.assertEqual(
            self.dialogs, [], "An unexpected modal dialog interrupted the workflow"
        )

    def wait_until(self, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while not predicate():
            self.app.processEvents()
            if time.monotonic() >= deadline:
                self.fail("GUI operation did not reach the expected state")
            time.sleep(0.001)
        self.app.processEvents()

    def run_action(self, tab, button, log, progress, succeeds=True):
        self.assertFalse(getattr(tab, "_jobs", []))
        print(
            f"GUI action: {button.text()}; expect {'success' if succeeds else 'failure'}",
            flush=True,
        )
        button.click()
        self.assertFalse(button.isEnabled())
        self.assertEqual(len(tab._jobs), 1)
        job = tab._jobs[0]
        thread_destroyed = []
        job._thread.destroyed.connect(lambda *_: thread_destroyed.append(True))
        worker = job.worker
        self.wait_until(lambda: not tab._jobs)
        self.app.sendPostedEvents(None, GUI.QEvent.Type.DeferredDelete)
        self.assertEqual(thread_destroyed, [True])
        self.assertIsNotNone(worker.proc)
        self.assertEqual(worker.proc.returncode == 0, succeeds, log.toPlainText())
        self.assertTrue(button.isEnabled())
        self.assertTrue(progress.isHidden())
        self.assertNotIn(self.password, log.toPlainText())
        return log.toPlainText()

    def prepare_compress(self, encrypted):
        tab = self.compress
        tab.src.edit.setText(str(self.input))
        tab.dst.edit.setText(str(self.archive))
        tab.codec.setCurrentText("VaptVupt")
        tab.level.setValue(9)
        tab.pw.setText(self.password if encrypted else "")

    def assert_extracted(self, output):
        actual = {
            p.relative_to(output).as_posix(): p.read_bytes()
            for p in output.rglob("*")
            if p.is_file()
        }
        # collect_files retains an absolute source path minus its namespace
        # prefix; it does not flatten a selected directory to its basename.
        prefix = self.input.as_posix()[len(self.input.drive) :].lstrip("/")
        expected = {f"{prefix}/{name}": data for name, data in self.files.items()}
        self.assertEqual(set(actual), set(expected))
        for name, data in expected.items():
            self.assertTrue(actual[name] == data, f"Extracted bytes differ: {name}")

    def roundtrip(self, encrypted):
        self.prepare_compress(encrypted)
        log = self.run_action(
            self.compress, self.compress.btn, self.compress.log, self.compress.progress
        )
        self.assertIn("Done.", log)
        self.assertRegex(log, r"Codec:\s+VaptVupt \(level 9\)")
        self.assertTrue(self.archive.is_file())
        if encrypted:
            self.assertIn("-p [redacted]", log)
        self.verify.varc.edit.setText(str(self.archive))
        self.verify.iarc.edit.setText(str(self.archive))
        self.verify.ibtn.click()
        self.assertRegex(
            self.verify.ilog.toPlainText(),
            r"Encrypted:\s+" + ("YES" if encrypted else "no"),
        )
        self.assertEqual(
            GUI._detect_archive_enc(str(self.archive))[0],
            "password" if encrypted else "none",
        )
        self.extract.arc.edit.setText(str(self.archive))
        if encrypted:
            for tab, button, log in (
                (self.verify, self.verify.vbtn, self.verify.vlog),
                (self.extract, self.extract.btn, self.extract.log),
            ):
                button.click()
                self.assertFalse(getattr(tab, "_jobs", []))
                self.assertTrue(button.isEnabled())
                self.assertIn("password-encrypted", log.toPlainText())
            wrong = "Incorrect-fixture-only-818!"
            self.verify.vpw.setText(wrong)
            self.extract.pw.setText(wrong)
            output = self.root / "wrong-password"
            self.extract.out.edit.setText(str(output))
            for tab, button, log, progress, failure in (
                (
                    self.verify,
                    self.verify.vbtn,
                    self.verify.vlog,
                    self.verify.vprogress,
                    "Verification failed.",
                ),
                (
                    self.extract,
                    self.extract.btn,
                    self.extract.log,
                    self.extract.progress,
                    "Extraction failed.",
                ),
            ):
                text = self.run_action(tab, button, log, progress, succeeds=False)
                self.assertIn(failure, text)
                self.assertNotIn(wrong, text)
            self.assertFalse(output.exists() and any(output.rglob("*")))
        self.verify.vpw.setText(self.password if encrypted else "")
        self.extract.pw.setText(self.password if encrypted else "")
        text = self.run_action(
            self.verify, self.verify.vbtn, self.verify.vlog, self.verify.vprogress
        )
        self.assertIn("All checksums passed.", text)
        # Reuse the same widgets and worker lifecycle for two complete reads.
        for attempt in range(2):
            output = self.root / f"extracted-{attempt}"
            self.extract.out.edit.setText(str(output))
            self.run_action(
                self.extract, self.extract.btn, self.extract.log, self.extract.progress
            )
            self.assert_extracted(output)

    def test_plain_vaptvupt_archive_actions(self):
        self.roundtrip(encrypted=False)

    @unittest.skipUnless(os.name == "posix", "Markup filenames require POSIX paths")
    def test_markup_in_a_real_archive_path_stays_literal_in_the_log(self):
        self.archive = self.root / "<b>backup &amp; ação.zupt"
        self.roundtrip(encrypted=False)
        self.assertIn(self.archive.name, self.compress.log.toPlainText())

    def test_password_vaptvupt_archive_actions(self):
        self.roundtrip(encrypted=True)

    def test_job_preserves_qobject_thread_affinity_method(self):
        tab = self.compress
        self.assertFalse(getattr(tab, "_jobs", []))
        job = GUI._Job(tab, ["--version"], tab.btn, tab.log, tab.progress)
        tab._jobs = [job]
        try:
            self.assertIs(job.thread(), tab.thread())
            self.assertIs(job.worker.thread(), job._thread)
            self.assertIs(job._thread.thread(), tab.thread())
        finally:
            job.start()
            self.wait_until(lambda: not tab._jobs)

    def test_completed_jobs_release_qobjects_before_window_close(self):
        tab = self.compress
        self.assertEqual(tab.findChildren(GUI._Job), [])
        for attempt in range(3):
            observers = {
                name: DeletionObserver(self.window)
                for name in ("job", "thread", "worker")
            }
            GUI.run_async(tab, ["--version"], tab.btn, tab.log, tab.progress)
            self.assertEqual(len(tab._jobs), 1)
            job = tab._jobs[0]
            # Require native cleanup even while its Python wrapper stays alive.
            worker = job.worker
            obj = None
            for name, obj in (
                ("job", job),
                ("thread", job._thread),
                ("worker", job.worker),
            ):
                # PyQt may discard a plain callback for a destroyed worker.
                # A retained QObject slot receives the queued signal without
                # converting the already-deleted QObject* argument.
                obj.destroyed.connect(observers[name].record)
            del obj
            self.wait_until(lambda worker=worker: worker.proc is not None)
            process = worker.proc
            self.wait_until(lambda: not tab._jobs)
            self.assertEqual(process.returncode, 0, tab.log.toPlainText())
            del job
            self.app.sendPostedEvents(None, GUI.QEvent.Type.DeferredDelete)
            self.app.processEvents()
            self.assertTrue(self.window.isVisible())
            self.assertEqual(
                tab.findChildren(GUI._Job),
                [],
                f"Completed job {attempt + 1} remains parented to the tab",
            )
            self.assertEqual(
                {name: observer.calls for name, observer in observers.items()},
                {"job": [True], "thread": [True], "worker": [True]},
            )
            for observer in observers.values():
                self.assertEqual(observer.thread(), self.app.thread())
                self.assertEqual(observer.callback_threads, [self.app.thread()])

    def test_job_finishing_during_close_confirmation_does_not_use_deleted_thread(self):
        tab = self.compress
        self.assertTrue(self.window.isVisible())
        GUI.run_async(tab, ["--version"], tab.btn, tab.log, tab.progress)
        job = tab._jobs[0]
        worker = job.worker
        destroyed = []
        job.destroyed.connect(lambda *_: destroyed.append(True))

        def finish_before_confirmation(*args, **kwargs):
            self.wait_until(lambda: not tab._jobs)
            self.app.sendPostedEvents(None, GUI.QEvent.Type.DeferredDelete)
            self.app.processEvents()
            self.assertTrue(self.window.isVisible())
            self.assertEqual(destroyed, [True])
            return GUI.QMessageBox.StandardButton.Yes

        callback_errors = []
        callback_stderr = io.StringIO()
        with (
            patch.object(
                sys,
                "excepthook",
                side_effect=lambda kind, error, trace: callback_errors.append(
                    (kind.__name__, str(error))
                ),
            ),
            patch.object(sys, "stderr", callback_stderr),
            patch.object(
                GUI.QMessageBox, "warning", side_effect=finish_before_confirmation
            ) as question,
        ):
            accepted = self.window.close()
        self.assertEqual(callback_errors, [], callback_stderr.getvalue())
        self.assertNotIn("Error calling Python override", callback_stderr.getvalue())
        question.assert_called_once()
        self.assertEqual(destroyed, [True])
        self.assertIsNotNone(worker.proc)
        self.assertEqual(worker.proc.returncode, 0, tab.log.toPlainText())
        self.assertTrue(accepted)
        self.assertFalse(self.window.isVisible())

    def test_cancel_before_worker_start(self):
        args = [
            "compress",
            "--vv",
            "-p",
            self.password,
            str(self.archive),
            str(self.input),
        ]
        tab = self.compress
        job = GUI._Job(tab, args, tab.btn, tab.log, tab.progress)
        tab._jobs = [job]
        thread_destroyed = []
        job._thread.destroyed.connect(lambda *_: thread_destroyed.append(True))
        worker = job.worker
        job.worker.cancel()
        job.start()
        self.wait_until(lambda: not tab._jobs)
        self.app.sendPostedEvents(None, GUI.QEvent.Type.DeferredDelete)
        self.assertEqual(thread_destroyed, [True])
        self.assertIsNotNone(worker.proc)
        self.assertNotEqual(worker.proc.returncode, 0)
        self.assertNotIn(self.password, tab.log.toPlainText())

    def test_window_close_cancels_a_running_cli_and_joins_the_worker(self):
        # A bounded synthetic file keeps real compression live long enough to
        # synchronize on Popen, instead of guessing a sleep duration.
        with (self.input / "large.bin").open("wb") as output:
            for _ in range(32):
                output.write(bytes(range(256)) * 4096)
        self.prepare_compress(encrypted=True)
        self.compress.btn.click()
        job = self.compress._jobs[0]
        thread_destroyed = []
        job._thread.destroyed.connect(lambda *_: thread_destroyed.append(True))
        self.wait_until(lambda: job.worker.proc is not None)
        process = job.worker.proc
        self.assertIsNone(process.poll(), "CLI finished before cancellation coverage")
        with patch.object(
            GUI.QMessageBox, "warning", return_value=GUI.QMessageBox.StandardButton.Yes
        ) as question:
            self.assertTrue(self.window.close())
        question.assert_called_once()
        self.wait_until(lambda: not self.compress._jobs)
        self.app.sendPostedEvents(None, GUI.QEvent.Type.DeferredDelete)
        self.assertEqual(thread_destroyed, [True])
        self.assertIsNotNone(process.poll())
        self.assertNotEqual(process.returncode, 0)


class SupervisorTests(unittest.TestCase):
    def test_abrupt_success_exit_does_not_approve_the_suite(self):
        self.check_failure("import os\nos._exit(0)\n")

    def test_nonzero_exit_with_a_completion_marker_is_rejected(self):
        self.check_failure(f"import os\nprint({COMPLETE!r}, flush=True)\nos._exit(1)\n")

    def check_failure(self, module_source):
        with tempfile.TemporaryDirectory(prefix="zupt-gui-supervisor-") as directory:
            module = Path(directory) / "exit_fixture.py"
            module.write_text(module_source)
            environment = dict(os.environ, ZUPT_GUI_MODULE=str(module))
            result = subprocess.run(
                [sys.executable, __file__],
                env=environment,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("did not complete successfully", result.stderr)


if __name__ == "__main__":
    sys.argv.remove("--run-tests")
    result = unittest.main(verbosity=2, exit=False).result
    if result.wasSuccessful():
        print(COMPLETE, flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
