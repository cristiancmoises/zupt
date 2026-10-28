# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés

"""Execute the real CI credential gate against synthetic Git fixtures."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
STEP = "      - name: Credential material audit (paths only)"
CLEAN = "No private-key block, named token assignment, or credential-bearing URL found."


def credential_step(workflow: str) -> str:
    """Accept only the literal Bash block used by this specific CI step."""
    lines = workflow.splitlines()
    positions = [index for index, line in enumerate(lines) if line == STEP]
    if len(positions) != 1:
        raise ValueError("expected exactly one credential audit step")
    start = positions[0] + 1
    if lines[start : start + 2] != ["        shell: bash", "        run: |"]:
        raise ValueError("credential audit must use a literal Bash block")
    body = []
    for line in lines[start + 2 :]:
        if line and not line.startswith("          "):
            break
        body.append(line[10:])
    if not any(line.strip() for line in body):
        raise ValueError("credential audit block is empty")
    return "\n".join(body) + "\n"


class CredentialStepExtractionTests(unittest.TestCase):
    def test_missing_duplicate_empty_or_nonliteral_step_is_rejected(self) -> None:
        valid = STEP + "\n        shell: bash\n        run: |\n          exit 0\n"
        for invalid in (
            "",
            valid + valid,
            valid.replace("run: |", "run: >"),
            valid.replace("          exit 0\n", ""),
            valid.replace("shell: bash", "shell: sh"),
        ):
            with self.subTest(workflow=invalid), self.assertRaises(ValueError):
                credential_step(invalid)

    def test_extracts_only_the_selected_block(self) -> None:
        fixture = (
            STEP + "\n        shell: bash\n        run: |\n          exit 7\n"
            "      - name: Unrelated step\n        run: exit 0\n"
        )
        self.assertEqual(credential_step(fixture), "exit 7\n")


class CredentialGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bash = shutil.which("bash")
        self.git = shutil.which("git")
        self.assertIsNotNone(self.bash, "Bash is required, not an optional test")
        self.assertIsNotNone(self.git, "Git is required, not an optional test")
        self.body = credential_step(WORKFLOW.read_text(encoding="utf-8"))
        temporary = tempfile.TemporaryDirectory(prefix="zupt credential gate ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.repository = self.work / "repository"
        self.repository.mkdir()
        (self.work / "home").mkdir()
        (self.work / "tmp").mkdir()
        self.environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(self.work / "home"),
            "TMPDIR": str(self.work / "tmp"),
            "LC_ALL": "C",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        self.run_git("init", "--quiet")

    def run_git(self, *arguments: str) -> None:
        subprocess.run(
            [str(self.git), *arguments],
            cwd=self.repository,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )

    def run_gate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.bash), "-c", self.body],
            cwd=self.repository,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_real_git_accepts_no_match(self) -> None:
        (self.repository / "source.txt").write_text(
            "ordinary source\n"
            "-----BEGIN PUBLIC KEY-----\n"
            "-----BEGIN RSA PUBLIC KEY-----\n"
            "-----BEGIN CERTIFICATE-----\n"
        )
        self.run_git("add", "--", "source.txt")
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, CLEAN + "\n")
        self.assertEqual(result.stderr, "")

    def test_ambient_git_overrides_cannot_redirect_fixtures(self) -> None:
        outside = self.work / "outside"
        self.run_git("init", "--quiet", str(outside))
        (outside / "source.txt").write_text("outside sentinel\n")
        self.run_git("-C", str(outside), "add", "--", "source.txt")
        index = outside / ".git/index"
        before = index.read_bytes()
        overrides = {
            "GIT_DIR": str(outside / ".git"),
            "GIT_WORK_TREE": str(outside),
            "GIT_INDEX_FILE": str(index),
            "GIT_OBJECT_DIRECTORY": str(outside / ".git/objects"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "GIT_CONFIG_VALUE_0": "false",
        }
        fixture = CredentialGateTests()
        try:
            with patch.dict(os.environ, overrides):
                fixture.setUp()
            (fixture.repository / "source.txt").write_text("private fixture\n")
            fixture.run_git("add", "--", "source.txt")
            self.assertTrue((fixture.repository / ".git/index").is_file())
            self.assertFalse(set(overrides) & fixture.environment.keys())
            self.assertEqual(index.read_bytes(), before)
        finally:
            fixture.doCleanups()

    def test_real_git_rejects_matches_without_printing_contents(self) -> None:
        samples = (
            "-----BEGIN " + "PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----",
            "https://dummy:" + "x" * 24 + "@example.invalid/",
            "gh" + "p_" + "x" * 40,
            "github_" + "pat_" + "x" * 24,
            "gl" + "pat-" + "x" * 24,
            "AK" + "IA" + "X" * 16,
            "xox" + "b-" + "x" * 24,
            "FORGEJO_TOKEN=" + "x" * 24,
        )
        for index, sample in enumerate(samples):
            with self.subTest(pattern=index):
                (self.repository / "suspicious file.txt").write_text(sample + "\n")
                self.run_git("add", "--", "suspicious file.txt")
                result = self.run_gate()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(CLEAN, result.stdout + result.stderr)
                self.assertIn("suspicious file.txt", result.stderr)
                self.assertNotIn(sample, result.stdout + result.stderr)

    def test_git_errors_and_inconsistent_results_never_report_clean(self) -> None:
        shim = self.work / "bin"
        shim.mkdir()
        executable = shim / "git"
        self.environment["PATH"] = str(shim) + os.pathsep + os.environ["PATH"]
        for status, output in (
            (128, ""),
            (128, "source.txt\n"),
            (1, "source.txt\n"),
            (0, ""),
            (127, ""),
        ):
            with self.subTest(status=status, output=output):
                diagnostic = "synthetic git grep error\n" if status > 1 else ""
                executable.write_text(
                    f"#!{self.bash}\n"
                    "[[ $1 == grep && $2 == -Il && $3 == -E && $4 == -- ]] || exit 99\n"
                    f"printf '%s' {shlex.quote(output)}\n"
                    f"printf '%s' {shlex.quote(diagnostic)} >&2\n"
                    f"exit {status}\n"
                )
                executable.chmod(0o700)
                result = self.run_gate()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(CLEAN, result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stdout + result.stderr)
                if diagnostic:
                    self.assertIn(diagnostic, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
